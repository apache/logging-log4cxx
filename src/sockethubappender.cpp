/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/net/sockethubappender.h>

#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/synchronized.h>
#include <apr_atomic.h>
#include <apr_thread_proc.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(SocketHubAppender)

int SocketHubAppender::DEFAULT_PORT = 4560;

SocketHubAppender::~SocketHubAppender()
{
	finalize();
}

SocketHubAppender::SocketHubAppender()
 : port(DEFAULT_PORT), locationInfo(false), oosList(), thread()
{
}

SocketHubAppender::SocketHubAppender(int port)
 : port(port), locationInfo(false), oosList(), thread()
{
	startServer();
}

void SocketHubAppender::activateOptions()
{
	startServer();
}

void SocketHubAppender::setOption(const String& option,
	const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, _T("port")))
	{
		setPort(OptionConverter::toInt(value, DEFAULT_PORT));
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("locationinfo")))
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
	apr_uint32_t wasClosed = apr_atomic_xchg32(&closed, 1);
	if (wasClosed) return;

	LOGLOG_DEBUG(_T("closing SocketHubAppender ") << getName());
    //
	//  wait until the server thread completes
	//
	thread.join();

	synchronized sync(mutex);
	// close all of the connections
	LOGLOG_DEBUG(_T("closing client connections"));
	for (std::vector<helpers::SocketOutputStreamPtr>::iterator iter = oosList.begin();
	     iter != oosList.end();
		 iter++) {
		 if ( (*iter) != NULL) {
			 try {
				(*iter)->close();
				*iter = NULL;
			 } catch(SocketException& e) {
				LogLog::error(_T("could not close oos: "), e);
			 }
		 }
	 }
	oosList.erase(oosList.begin(), oosList.end());


	LOGLOG_DEBUG(_T("SocketHubAppender ") << getName() << _T(" closed"));
}

void SocketHubAppender::append(const spi::LoggingEventPtr& event)
{

	// if no open connections, exit now
	if(oosList.empty())
	{
		return;
	}


	// loop through the current set of open connections, appending the event to each
	std::vector<SocketOutputStreamPtr>::iterator it = oosList.begin();
	std::vector<SocketOutputStreamPtr>::iterator itEnd = oosList.end();
	while(it != itEnd)
	{
		SocketOutputStreamPtr oos = *it;

		// list size changed unexpectedly? Just exit the append.
		if (oos == 0)
		{
			break;
		}

		try
		{
			event->write(oos);
			oos->flush();
			it++;
		}
		catch(SocketException&)
		{
			// there was an io exception so just drop the connection
			it = oosList.erase(it);
			LOGLOG_DEBUG(_T("dropped connection"));
		}
	}
}

void SocketHubAppender::startServer()
{
	thread.run(pool, monitor, this);
}

void* APR_THREAD_FUNC SocketHubAppender::monitor(apr_thread_t* thread, void* data) {
	SocketHubAppender* pThis = (SocketHubAppender*) data;

	ServerSocket * serverSocket = 0;

	try
	{
		serverSocket = new ServerSocket(pThis->port);
		serverSocket->setSoTimeout(1000);
	}
	catch (SocketException& e)
	{
		LogLog::error(_T("exception setting timeout, shutting down server socket."), e);
		return NULL;
	}

	apr_uint32_t stopRunning = apr_atomic_read32(&pThis->closed);
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
			LogLog::error(_T("exception accepting socket, shutting down server socket."), e);
			stopRunning = 1;
		}
		catch (IOException& e)
		{
			LogLog::error(_T("exception accepting socket."), e);
		}

		// if there was a socket accepted
		if (socket != 0)
		{
			try
			{
				InetAddress remoteAddress = socket->getInetAddress();
				LOGLOG_DEBUG(_T("accepting connection from ") << remoteAddress.getHostName()
					<< _T(" (") + remoteAddress.getHostAddress() + _T(")"));

				// create an ObjectOutputStream
				SocketOutputStreamPtr oos = socket->getOutputStream();

				// add it to the oosList.
				synchronized sync(pThis->mutex);
				pThis->oosList.push_back(oos);
			}
			catch (IOException& e)
			{
				LogLog::error(_T("exception creating output stream on socket."), e);
			}
		}
	}

	delete serverSocket;
	return NULL;
}

