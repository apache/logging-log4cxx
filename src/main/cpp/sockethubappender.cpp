/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#if defined(_MSC_VER)
	#pragma warning ( disable: 4231 4251 4275 4786 )
#endif

#include <log4cxx/net/sockethubappender.h>

#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/spi/loggingevent.h>
#include <apr_atomic.h>
#include <apr_thread_proc.h>
#include <log4cxx/helpers/objectoutputstream.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/private/appenderskeleton_priv.h>
#include <mutex>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(SocketHubAppender)

int SocketHubAppender::DEFAULT_PORT = 4560;

struct SocketHubAppender::SocketHubAppenderPriv : public AppenderSkeletonPrivate
{
	SocketHubAppenderPriv(int port) :
		AppenderSkeletonPrivate(),
		port(port),
		streams(),
		locationInfo(false),
		thread() {}

	int port;
	ObjectOutputStreamList streams;
	bool locationInfo;
	std::thread thread;
};

#define _priv static_cast<SocketHubAppenderPriv*>(m_priv.get())

SocketHubAppender::~SocketHubAppender()
{
	finalize();
}

SocketHubAppender::SocketHubAppender()
	: AppenderSkeleton (std::make_unique<SocketHubAppenderPriv>(SocketHubAppender::DEFAULT_PORT))
{
}

SocketHubAppender::SocketHubAppender(int port1)
	: AppenderSkeleton (std::make_unique<SocketHubAppenderPriv>(port1))
{
	startServer();
}

void SocketHubAppender::activateOptions(Pool& /* p */ )
{
	startServer();
}

void SocketHubAppender::setOption(const LogString& option,
	const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("PORT"), LOG4CXX_STR("port")))
	{
		setPort(OptionConverter::toInt(value, DEFAULT_PORT));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("locationinfo")))
	{
		setLocationInfo(OptionConverter::toBoolean(value, true));
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}


void SocketHubAppender::close()
{
	{
		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);

		if (_priv->closed)
		{
			return;
		}

		_priv->closed = true;
	}

	LogLog::debug(LOG4CXX_STR("closing SocketHubAppender ") + getName());

	//
	//  wait until the server thread completes
	//
	if ( _priv->thread.joinable() )
	{
		_priv->thread.join();
	}

	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	// close all of the connections
	LogLog::debug(LOG4CXX_STR("closing client connections"));

	for (std::vector<helpers::ObjectOutputStreamPtr>::iterator iter = _priv->streams.begin();
		iter != _priv->streams.end();
		iter++)
	{
		if ( (*iter) != NULL)
		{
			try
			{
				(*iter)->close(_priv->pool);
			}
			catch (SocketException& e)
			{
				LogLog::error(LOG4CXX_STR("could not close socket: "), e);
			}
		}
	}

	_priv->streams.erase(_priv->streams.begin(), _priv->streams.end());


	LogLog::debug(LOG4CXX_STR("SocketHubAppender ")
		+ getName() + LOG4CXX_STR(" closed"));
}

void SocketHubAppender::append(const spi::LoggingEventPtr& event, Pool& p)
{

	// if no open connections, exit now
	if (_priv->streams.empty())
	{
		return;
	}

	LogString ndcVal;
	event->getNDC(ndcVal);
	event->getThreadName();
	// Get a copy of this thread's MDC.
	event->getMDCCopy();


	// loop through the current set of open connections, appending the event to each
	std::vector<ObjectOutputStreamPtr>::iterator it = _priv->streams.begin();
	std::vector<ObjectOutputStreamPtr>::iterator itEnd = _priv->streams.end();

	while (it != itEnd)
	{
		// list size changed unexpectedly? Just exit the append.
		if (*it == 0)
		{
			break;
		}

		try
		{
			//          event->write(**it, p);
			(*it)->flush(p);
			it++;
		}
		catch (std::exception& e)
		{
			// there was an io exception so just drop the connection
			it = _priv->streams.erase(it);
			itEnd = _priv->streams.end();
			LogLog::debug(LOG4CXX_STR("dropped connection"), e);
		}
	}
}

void SocketHubAppender::startServer()
{
	_priv->thread = ThreadUtility::instance()->createThread( LOG4CXX_STR("SocketHub"), &SocketHubAppender::monitor, this );
}

void SocketHubAppender::monitor()
{
	ServerSocketUniquePtr serverSocket = 0;

	try
	{
		serverSocket = ServerSocket::create(_priv->port);
		serverSocket->setSoTimeout(1000);
	}
	catch (SocketException& e)
	{
		LogLog::error(LOG4CXX_STR("exception setting timeout, shutting down server socket."), e);
		return;
	}

	bool stopRunning = _priv->closed;

	while (!stopRunning)
	{
		SocketPtr socket;

		try
		{
			socket = serverSocket->accept();
		}
		catch (InterruptedIOException&)
		{
			// timeout occurred, so just loop
		}
		catch (SocketException& e)
		{
			LogLog::error(LOG4CXX_STR("exception accepting socket, shutting down server socket."), e);
			stopRunning = true;
		}
		catch (IOException& e)
		{
			LogLog::error(LOG4CXX_STR("exception accepting socket."), e);
		}

		// if there was a socket accepted
		if (socket != 0)
		{
			try
			{
				InetAddressPtr remoteAddress = socket->getInetAddress();
				LogLog::debug(LOG4CXX_STR("accepting connection from ")
					+ remoteAddress->getHostName()
					+ LOG4CXX_STR(" (")
					+ remoteAddress->getHostAddress()
					+ LOG4CXX_STR(")"));

				// add it to the oosList.
				std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
				OutputStreamPtr os(new SocketOutputStream(socket));
				Pool p;
				ObjectOutputStreamPtr oos(new ObjectOutputStream(os, p));
				_priv->streams.push_back(oos);
			}
			catch (IOException& e)
			{
				LogLog::error(LOG4CXX_STR("exception creating output stream on socket."), e);
			}
		}

		stopRunning = (stopRunning || _priv->closed);
	}
}

void SocketHubAppender::setPort(int port1)
{
	_priv->port = port1;
}

int SocketHubAppender::getPort() const
{
	return _priv->port;
}

void SocketHubAppender::setLocationInfo(bool locationInfo1)
{
	_priv->locationInfo = locationInfo1;
}

bool SocketHubAppender::getLocationInfo() const
{
	return _priv->locationInfo;
}
