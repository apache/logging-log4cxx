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

#include <log4cxx/net/socketappenderskeleton.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/synchronized.h>
#include <apr_time.h>
#include <apr_atomic.h>
#include <apr_thread_proc.h>

//Define INT64_C for compilers that don't have it
#if (!defined(INT64_C))
#define INT64_C(value)  int64_t(value)
#endif


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;


SocketAppenderSkeleton::SocketAppenderSkeleton(int defaultPort, int reconnectionDelay)
: port(defaultPort), reconnectionDelay(reconnectionDelay),
locationInfo(false),
remoteHost(), address(), os(), thread()

{
}

SocketAppenderSkeleton::SocketAppenderSkeleton(unsigned long address, int port, int delay)
: port(port), reconnectionDelay(delay),
locationInfo(false),
os(), thread() {
    this->address.address = address;
    remoteHost = this->address.getHostName();
}

SocketAppenderSkeleton::SocketAppenderSkeleton(const String& host, int port, int delay)
: address(InetAddress::getByName(host)), port(port),
reconnectionDelay(delay), locationInfo(false),
remoteHost(host),
os(), thread()

{
}

SocketAppenderSkeleton::~SocketAppenderSkeleton()
{
	finalize();
}

void SocketAppenderSkeleton::activateOptions()
{
	connect();
}

void SocketAppenderSkeleton::setOption(const String& option,
	const String& value, int defaultPort, int defaultDelay)
{
	if (StringHelper::equalsIgnoreCase(option, _T("remotehost")))
	{
		setRemoteHost(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("port")))
	{
		setPort(OptionConverter::toInt(value, defaultPort));
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("locationinfo")))
	{
		setLocationInfo(OptionConverter::toBoolean(value, false));
	}
	else if (StringHelper::equalsIgnoreCase(option, _T("reconnectiondelay")))
	{
		setReconnectionDelay(OptionConverter::toInt(value, defaultDelay));
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}

void SocketAppenderSkeleton::append(const spi::LoggingEventPtr& event)
{
	if(address.address == 0)
	{
		errorHandler->error(
			_T("No remote host is set for appender named \"") +
			name+_T("\"."));
		return;
	}

	if(os != 0) try
	{
		renderEvent(event, os);

		// flush to socket
		os->flush();
	}
	catch(SocketException& e)
	{
		os = 0;
		LogLog::warn(_T("Detected problem with connection: "), e);

		if(reconnectionDelay > 0)
		{
			fireConnector();
		}

	}
}



void SocketAppenderSkeleton::close()
{
    apr_uint32_t wasClosed = apr_atomic_xchg32(&closed, 1);
	if (wasClosed) return;
	cleanUp();
}

void SocketAppenderSkeleton::cleanUp()
{
	if(os != 0)
	{
		try
		{
			os->close();
		}
		catch(IOException& e)
		{
			LogLog::error(_T("Could not close socket :"), e);
		}

		os = 0;
	}

	thread.join();
}

void SocketAppenderSkeleton::connect()
{
	if(address.address == 0)
	{
		return;
	}

	try
	{
		// First, close the previous connection if any.
		cleanUp();

		SocketPtr socket = new Socket(address, port);
		os = socket->getOutputStream();
	}
	catch(SocketException& e)
	{
		String msg = _T("Could not connect to remote log4cxx server at [")

			+address.getHostName()+_T("].");

		if(reconnectionDelay > 0)
		{
			msg += _T(" We will try again later. ");
		}

		fireConnector(); // fire the connector thread

		LogLog::error(msg, e);
	}
}


void SocketAppenderSkeleton::fireConnector()
{
	synchronized sync(mutex);
	if (thread.isActive()) {
		thread.run(pool, monitor, this);
	}
}

void* APR_THREAD_FUNC SocketAppenderSkeleton::monitor(apr_thread_t* thread, void* data) {
	SocketAppenderSkeleton* socketAppender = (SocketAppenderSkeleton*) data;
	SocketPtr socket;
	apr_uint32_t isClosed = apr_atomic_read32(&socketAppender->closed);
	while(!isClosed)
	{
		try
		{
			apr_sleep(APR_INT64_C(1000) * socketAppender->reconnectionDelay);
			LogLog::debug(_T("Attempting connection to ")
				+socketAppender->address.getHostName());
			socket = new Socket(socketAppender->address, socketAppender->port);

			synchronized sync(socketAppender->mutex);
			{
				socketAppender->os = socket->getOutputStream();
				LogLog::debug(_T("Connection established. Exiting connector thread."));
				socketAppender->thread.ending();
				return NULL;
			}
		}
		catch(ConnectException&)
		{
			LogLog::debug(_T("Remote host ")
				+socketAppender->address.getHostName()
				+_T(" refused connection."));
		}
		catch(IOException& e)
		{
			LogLog::debug(_T("Could not connect to ")
				 +socketAppender->address.getHostName()
				 +_T(". Exception is ") + e.what());
		}
	    isClosed = apr_atomic_read32(&socketAppender->closed);
	}

	LogLog::debug(_T("Exiting Connector.run() method."));
	return NULL;
}
