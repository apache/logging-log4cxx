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

#include <log4cxx/net/telnetappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/synchronized.h>
#include <apr_thread_proc.h>
#include <apr_atomic.h>
#include <apr_strings.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;

IMPLEMENT_LOG4CXX_OBJECT(TelnetAppender)

int TelnetAppender::DEFAULT_PORT = 23;


TelnetAppender::TelnetAppender() 
   : port(23), 
     sh(), 
	 connections(20), 
	 activeConnections(0),
	 serverSocket(NULL)
{
}

TelnetAppender::~TelnetAppender()
{
	finalize();
	delete serverSocket;
}

void TelnetAppender::activateOptions()
{
	if (serverSocket == NULL) {
		serverSocket = new ServerSocket(port);
	}
	sh.run(pool, acceptConnections, this);
}

void TelnetAppender::setOption(const String& option,
	const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, _T("port")))
	{
		setPort(OptionConverter::toInt(value, DEFAULT_PORT));
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}

void TelnetAppender::close()
{
	apr_uint32_t wasClosed = apr_atomic_xchg32(&closed, 1);
	if (wasClosed) return;

	synchronized sync(mutex);
	sh.stop();

	for(ConnectionList::iterator iter = connections.begin();
	    iter != connections.end();
		iter++) {
		if (iter->first != NULL) {
			try {
				iter->second->close();
			} catch(Exception& ex) {
			}
			iter->second = NULL;
			try {
				iter->first->close();
			} catch(Exception& ex) {
			}
			iter->first = NULL;
		}
	}

	if (serverSocket != NULL) {
		try {
			serverSocket->close();
		} catch(Exception&) {
		}
	}

	activeConnections = 0;
}

void TelnetAppender::append(const spi::LoggingEventPtr& event)
{
	apr_uint32_t count = apr_atomic_read32(&activeConnections);
	if (count > 0) {
		StringBuffer os;

		this->layout->format(os, event);
		os << "\r\n";

		synchronized sync(this->mutex);

		for (ConnectionList::iterator iter = connections.begin();
			 iter != connections.end();
			 iter++) {
			if (iter->first != NULL) {
				try {
					iter->second->write(os.str());
					iter->second->flush();
				} catch(Exception& ex) {
					// The client has closed the connection, remove it from our list:
					iter->first = NULL;
					iter->second = NULL;
					apr_atomic_dec32(&activeConnections);
				}
			}
		}
	}
}


void* APR_THREAD_FUNC TelnetAppender::acceptConnections(apr_thread_t* thread, void* data) {
	TelnetAppender* pThis = (TelnetAppender*) data;

 	try
	{
		SocketPtr newClient = pThis->serverSocket->accept();
		SocketOutputStreamPtr os = newClient->getOutputStream();
		apr_uint32_t done = apr_atomic_read32(&pThis->closed);
		if (done) {
			os->write("Log closed.\r\n");
			os->flush();
			newClient->close();
			return NULL;
		}

		apr_uint32_t count = apr_atomic_read32(&pThis->activeConnections);
		if (count > pThis->connections.size()) {
			os->write("Too many connections.\r\n");
			os->flush();
			newClient->close();
		} else {
			std::string oss("TelnetAppender v1.0 (");
			oss += apr_itoa(pThis->pool, count);
			oss += " active connections)\r\n\r\n";
			os->write(oss);
			os->flush();

			//
			//   find unoccupied connection
			//
			synchronized sync(pThis->mutex);
			for(ConnectionList::iterator iter = pThis->connections.begin();
				iter != pThis->connections.end();
				iter++) {
				if (iter->first == NULL) {
					iter->first = newClient;
					iter->second = os;
					apr_atomic_inc32(&pThis->activeConnections);
					break;
				}
			}
		}
	} catch(Exception& e) {
		LogLog::error(_T("Encountered error while in SocketHandler loop."), e);
	}
	return NULL;
}




