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

#define __STDC_CONSTANT_MACROS
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
#include <log4cxx/helpers/transcoder.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;

#if APR_HAS_THREADS

SocketAppenderSkeleton::SocketAppenderSkeleton(int defaultPort, int reconnectionDelay1)
:  pool(),
   remoteHost(),
   address(),
   port(defaultPort),
   os(),
   reconnectionDelay(reconnectionDelay1),
   locationInfo(false),
   thread() {
}

SocketAppenderSkeleton::SocketAppenderSkeleton(InetAddressPtr address1, int port1, int delay)
:
   pool(),
   remoteHost(),
   address(address1),
   port(port1),
   os(),
   reconnectionDelay(delay),
   locationInfo(false),
   thread() {
    remoteHost = this->address->getHostName();
}

SocketAppenderSkeleton::SocketAppenderSkeleton(const LogString& host, int port1, int delay)
:   pool(),
    remoteHost(host),
    address(InetAddress::getByName(host)),
        port(port1),
    os(),
    reconnectionDelay(delay),
        locationInfo(false),
        thread() {
}

SocketAppenderSkeleton::~SocketAppenderSkeleton()
{
        finalize();
}

void SocketAppenderSkeleton::activateOptions(Pool& /* p */ )
{
        connect();
}

void SocketAppenderSkeleton::setOption(const LogString& option,
        const LogString& value, int defaultPort, int defaultDelay)
{
        if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("REMOTEHOST"), LOG4CXX_STR("remotehost")))
        {
                setRemoteHost(value);
        }
        else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("PORT"), LOG4CXX_STR("port")))
        {
                setPort(OptionConverter::toInt(value, defaultPort));
        }
        else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("locationinfo")))
        {
                setLocationInfo(OptionConverter::toBoolean(value, false));
        }
        else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("RECONNECTIONDELAY"), LOG4CXX_STR("reconnectiondelay")))
        {
                setReconnectionDelay(OptionConverter::toInt(value, defaultDelay));
        }
        else
        {
                AppenderSkeleton::setOption(option, value);
        }
}

void SocketAppenderSkeleton::append(const spi::LoggingEventPtr& event, Pool& p)
{
        if(address == 0)
        {
                errorHandler->error(
                        LOG4CXX_STR("No remote host is set for appender named \"") +
                        name+LOG4CXX_STR("\"."));
                return;
        }

        if(os != 0) try
        {
                renderEvent(event, os, p);

                // flush to socket
                os->flush();
        }
        catch(SocketException& e)
        {
                os = 0;
                LogLog::warn(LOG4CXX_STR("Detected problem with connection: "), e);

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
                        LogLog::error(LOG4CXX_STR("Could not close socket :"), e);
                }

                os = 0;
        }

        thread.join();
}

void SocketAppenderSkeleton::connect()
{
        if(address == 0)
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
                LogString msg = LOG4CXX_STR("Could not connect to remote log4cxx server at [")

                        +address->getHostName()+LOG4CXX_STR("].");

                if(reconnectionDelay > 0)
                {
                        msg += LOG4CXX_STR(" We will try again later. ");
                }

                fireConnector(); // fire the connector thread

                LogLog::error(msg, e);
        }
}


void SocketAppenderSkeleton::fireConnector()
{
        synchronized sync(mutex);
        if (thread.isActive()) {
                thread.run(monitor, this);
        }
}

void* APR_THREAD_FUNC SocketAppenderSkeleton::monitor(log4cxx_thread_t* /* thread */, void* data) {
        SocketAppenderSkeleton* socketAppender = (SocketAppenderSkeleton*) data;
        SocketPtr socket;
        apr_uint32_t isClosed = apr_atomic_read32(&socketAppender->closed);
        while(!isClosed)
        {
                try
                {
                        apr_sleep(APR_INT64_C(1000) * socketAppender->reconnectionDelay);
                        LogLog::debug(LOG4CXX_STR("Attempting connection to ")
                                +socketAppender->address->getHostName());
                        socket = new Socket(socketAppender->address, socketAppender->port);

                        synchronized sync(socketAppender->mutex);
                        {
                                socketAppender->os = socket->getOutputStream();
                                LogLog::debug(LOG4CXX_STR("Connection established. Exiting connector thread."));
                                socketAppender->thread.ending();
                                return NULL;
                        }
                }
                catch(ConnectException&)
                {
                        LogLog::debug(LOG4CXX_STR("Remote host ")
                                +socketAppender->address->getHostName()
                                +LOG4CXX_STR(" refused connection."));
                }
                catch(IOException& e)
                {
                        LogString exmsg;
                        log4cxx::helpers::Transcoder::decode(e.what(), exmsg);

                        LogLog::debug(((LogString) LOG4CXX_STR("Could not connect to "))
                                 + socketAppender->address->getHostName()
                                 + LOG4CXX_STR(". Exception is ")
                                 + exmsg);
                }
            isClosed = apr_atomic_read32(&socketAppender->closed);
        }

        LogLog::debug(LOG4CXX_STR("Exiting Connector.run() method."));
        return NULL;
}

#endif
