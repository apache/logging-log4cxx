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

#include <log4cxx/net/socketappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/synchronized.h>
#include <apr_time.h>
#include <apr_atomic.h>
#include <apr_thread_proc.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;

IMPLEMENT_LOG4CXX_OBJECT(SocketAppender)


// The default port number of remote logging server (4560)
int SocketAppender::DEFAULT_PORT                 = 4560;

// The default reconnection delay (30000 milliseconds or 30 seconds).
int SocketAppender::DEFAULT_RECONNECTION_DELAY   = 30000;



SocketAppender::SocketAppender() 
: SocketAppenderSkeleton(DEFAULT_PORT, DEFAULT_RECONNECTION_DELAY) {
}

SocketAppender::SocketAppender(unsigned long address, int port)
: SocketAppenderSkeleton(address, port, DEFAULT_RECONNECTION_DELAY) {
	connect();
}

SocketAppender::SocketAppender(const String& host, int port)
: SocketAppenderSkeleton(host, port, DEFAULT_RECONNECTION_DELAY) {
	connect();
}

SocketAppender::~SocketAppender()
{
}

void SocketAppender::renderEvent(const spi::LoggingEventPtr& event,
								 helpers::SocketOutputStreamPtr& os)
{
	event->write(os);
}

