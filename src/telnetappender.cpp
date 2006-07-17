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

#if APR_HAS_THREADS

IMPLEMENT_LOG4CXX_OBJECT(TelnetAppender)

/** The default telnet server port */
const int TelnetAppender::DEFAULT_PORT = 23;

/** The maximum number of concurrent connections */
const int TelnetAppender::MAX_CONNECTIONS = 20;

TelnetAppender::TelnetAppender()
  : port(DEFAULT_PORT), connections(MAX_CONNECTIONS),
    serverSocket(NULL), sh(), activeConnections(0)
{
}

TelnetAppender::~TelnetAppender()
{
        finalize();
        delete serverSocket;
}

void TelnetAppender::activateOptions(Pool& /* p */)
{
        if (serverSocket == NULL) {
                serverSocket = new ServerSocket(port);
        }
        sh.run(acceptConnections, this);
}

void TelnetAppender::setOption(const LogString& option,
        const LogString& value)
{
        if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("PORT"), LOG4CXX_STR("port")))
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

        SocketPtr nullSocket;
        SocketOutputStreamPtr nullStream;
        for(ConnectionList::iterator iter = connections.begin();
            iter != connections.end();
                iter++) {
                if (iter->first != NULL) {
                        try {
                                iter->second->close();
                        } catch(Exception& ex) {
                        }
                        iter->second = nullStream;
                        try {
                                iter->first->close();
                        } catch(Exception& ex) {
                        }
                        iter->first = nullSocket;
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

void TelnetAppender::append(const spi::LoggingEventPtr& event, Pool& /* p */)
{
        apr_uint32_t count = apr_atomic_read32(&activeConnections);
        if (count > 0) {
                LogString os;

                this->layout->format(os, event, pool);
                os.append(LOG4CXX_STR("\r\n"));

                SocketPtr nullSocket;
                SocketOutputStreamPtr nullStream;

                synchronized sync(this->mutex);


                for (ConnectionList::iterator iter = connections.begin();
                         iter != connections.end();
                         iter++) {
                        if (iter->first != NULL) {
                                try {
                                        iter->second->writeRaw(os);
                                        iter->second->flush();
                                } catch(Exception& ex) {
                                        // The client has closed the connection, remove it from our list:
                                        iter->first = nullSocket;
                                        iter->second = nullStream;
                                        apr_atomic_dec32(&activeConnections);
                                }
                        }
                }
        }
}

void* APR_THREAD_FUNC TelnetAppender::acceptConnections(log4cxx_thread_t* /* thread */, void* data) {
    TelnetAppender* pThis = (TelnetAppender*) data;

    // main loop; is left when This->closed is != 0 after an accept()
    while(true)
    {
        try
        {
                SocketPtr newClient = pThis->serverSocket->accept();
                SocketOutputStreamPtr os = newClient->getOutputStream();
                apr_uint32_t done = apr_atomic_read32(&pThis->closed);
                if (done) {
                        os->writeRaw(LOG4CXX_STR("Log closed.\r\n"));
                        os->flush();
                        newClient->close();
                        return NULL;
                }

                apr_uint32_t count = apr_atomic_read32(&pThis->activeConnections);
                if (count >= pThis->connections.size()) {
                        os->writeRaw(LOG4CXX_STR("Too many connections.\r\n"));
                        os->flush();
                        newClient->close();
                } else {
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

                        LogString oss(LOG4CXX_STR("TelnetAppender v1.0 ("));
                        oss += StringHelper::toString((int) count+1, pThis->pool);
                        oss += LOG4CXX_STR(" active connections)\r\n\r\n");
                        os->writeRaw(oss);
                        os->flush();
                }
        } catch(Exception& e) {
                LogLog::error(LOG4CXX_STR("Encountered error while in SocketHandler loop."), e);
        }
    }

    return NULL;
}

#endif
