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

#include <log4cxx/net/telnetappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/charsetencoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/private/appenderskeleton_priv.h>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::net;

IMPLEMENT_LOG4CXX_OBJECT(TelnetAppender)

struct TelnetAppender::TelnetAppenderPriv : public AppenderSkeletonPrivate
{
	TelnetAppenderPriv( int port, int maxConnections ) : AppenderSkeletonPrivate(),
		port(port),
		connections(maxConnections),
		encoding(LOG4CXX_STR("UTF-8")),
		encoder(CharsetEncoder::getUTF8Encoder()),
		sh(),
		activeConnections(0) {}

	int port;
	ConnectionList connections;
	LogString encoding;
	LOG4CXX_NS::helpers::CharsetEncoderPtr encoder;
	std::unique_ptr<helpers::ServerSocket> serverSocket;
	std::thread sh;
	size_t activeConnections;
};

#define _priv static_cast<TelnetAppenderPriv*>(m_priv.get())

/** The default telnet server port */
const int TelnetAppender::DEFAULT_PORT = 23;

/** The maximum number of concurrent connections */
const int TelnetAppender::MAX_CONNECTIONS = 20;

TelnetAppender::TelnetAppender()
	: AppenderSkeleton (std::make_unique<TelnetAppenderPriv>(DEFAULT_PORT, MAX_CONNECTIONS))
{
}

TelnetAppender::~TelnetAppender()
{
	finalize();
}

void TelnetAppender::activateOptions(Pool& /* p */)
{
	if (_priv->serverSocket == NULL)
	{
		_priv->serverSocket = ServerSocket::create(_priv->port);
		_priv->serverSocket->setSoTimeout(1000);
	}

	_priv->sh = ThreadUtility::instance()->createThread( LOG4CXX_STR("TelnetAppender"), &TelnetAppender::acceptConnections, this );
}

void TelnetAppender::setOption(const LogString& option,
	const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("PORT"), LOG4CXX_STR("port")))
	{
		setPort(OptionConverter::toInt(value, DEFAULT_PORT));
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("ENCODING"), LOG4CXX_STR("encoding")))
	{
		setEncoding(value);
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}

LogString TelnetAppender::getEncoding() const
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	return _priv->encoding;
}

void TelnetAppender::setEncoding(const LogString& value)
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);
	_priv->encoder = CharsetEncoder::getEncoder(value);
	_priv->encoding = value;
}


void TelnetAppender::close()
{
	std::lock_guard<std::recursive_mutex> lock(_priv->mutex);

	if (_priv->closed)
	{
		return;
	}

	_priv->closed = true;

	SocketPtr nullSocket;

	for (ConnectionList::iterator iter = _priv->connections.begin();
		iter != _priv->connections.end();
		iter++)
	{
		if (*iter != 0)
		{
			(*iter)->close();
			*iter = nullSocket;
		}
	}

	if (_priv->serverSocket != NULL)
	{
		try
		{
			_priv->serverSocket->close();
		}
		catch (Exception&)
		{
		}
	}

	if ( _priv->sh.joinable() )
	{
		_priv->sh.join();
	}

	_priv->activeConnections = 0;
}


void TelnetAppender::write(ByteBuffer& buf)
{
	for (ConnectionList::iterator iter = _priv->connections.begin();
		iter != _priv->connections.end();
		iter++)
	{
		if (*iter != 0)
		{
			try
			{
				ByteBuffer b(buf.current(), buf.remaining());
				(*iter)->write(b);
			}
			catch (Exception&)
			{
				// The client has closed the connection, remove it from our list:
				*iter = 0;
				_priv->activeConnections--;
			}
		}
	}
}

void TelnetAppender::writeStatus(const SocketPtr& socket, const LogString& msg, Pool& p)
{
	size_t bytesSize = msg.size() * 2;
	char* bytes = p.pstralloc(bytesSize);

	LogString::const_iterator msgIter(msg.begin());
	ByteBuffer buf(bytes, bytesSize);

	while (msgIter != msg.end())
	{
		_priv->encoder->encode(msg, msgIter, buf);
		buf.flip();
		socket->write(buf);
		buf.clear();
	}
}

void TelnetAppender::append(const spi::LoggingEventPtr& event, Pool& p)
{
	size_t count = _priv->activeConnections;

	if (count > 0)
	{
		LogString msg;
		_priv->layout->format(msg, event, _priv->pool);
		msg.append(LOG4CXX_STR("\r\n"));
		size_t bytesSize = msg.size() * 2;
		char* bytes = p.pstralloc(bytesSize);

		LogString::const_iterator msgIter(msg.begin());
		ByteBuffer buf(bytes, bytesSize);

		std::lock_guard<std::recursive_mutex> lock(_priv->mutex);

		while (msgIter != msg.end())
		{
			log4cxx_status_t stat = _priv->encoder->encode(msg, msgIter, buf);
			buf.flip();
			write(buf);
			buf.clear();

			if (CharsetEncoder::isError(stat))
			{
				LogString unrepresented(1, 0x3F /* '?' */);
				LogString::const_iterator unrepresentedIter(unrepresented.begin());
				stat = _priv->encoder->encode(unrepresented, unrepresentedIter, buf);
				buf.flip();
				write(buf);
				buf.clear();
				msgIter++;
			}
		}
	}
}

void TelnetAppender::acceptConnections()
{

	// main loop; is left when This->closed is != 0 after an accept()
	while (true)
	{
		try
		{
			SocketPtr newClient = _priv->serverSocket->accept();
			bool done = _priv->closed;

			if (done)
			{
				Pool p;
				writeStatus(newClient, LOG4CXX_STR("Log closed.\r\n"), p);
				newClient->close();

				break;
			}

			size_t count = _priv->activeConnections;

			if (count >= _priv->connections.size())
			{
				Pool p;
				writeStatus(newClient, LOG4CXX_STR("Too many connections.\r\n"), p);
				newClient->close();
			}
			else
			{
				//
				//   find unoccupied connection
				//
				std::lock_guard<std::recursive_mutex> lock(_priv->mutex);

				for (ConnectionList::iterator iter = _priv->connections.begin();
					iter != _priv->connections.end();
					iter++)
				{
					if (*iter == NULL)
					{
						*iter = newClient;
						_priv->activeConnections++;

						break;
					}
				}

				Pool p;
				LogString oss(LOG4CXX_STR("TelnetAppender v1.0 ("));
				StringHelper::toString((int) count + 1, p, oss);
				oss += LOG4CXX_STR(" active connections)\r\n\r\n");
				writeStatus(newClient, oss, p);
			}
		}
		catch (InterruptedIOException&)
		{
			if (_priv->closed)
			{
				break;
			}
		}
		catch (Exception& e)
		{
			if (!_priv->closed)
			{
				LogLog::error(LOG4CXX_STR("Encountered error while in SocketHandler loop."), e);
			}
			else
			{
				break;
			}
		}
	}

}

int TelnetAppender::getPort() const
{
	return _priv->port;
}

void TelnetAppender::setPort(int port1)
{
	_priv->port = port1;
}
