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

#include <log4cxx/net/xmlsocketappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/transform.h>
#include <apr_time.h>
#include <log4cxx/helpers/synchronized.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;
using namespace log4cxx::xml;

IMPLEMENT_LOG4CXX_OBJECT(XMLSocketAppender)

// The default port number of remote logging server (4560)
int XMLSocketAppender::DEFAULT_PORT                 = 4560;

// The default reconnection delay (30000 milliseconds or 30 seconds).
int XMLSocketAppender::DEFAULT_RECONNECTION_DELAY   = 30000;

const int XMLSocketAppender::MAX_EVENT_LEN          = 1024;

XMLSocketAppender::XMLSocketAppender()
: SocketAppenderSkeleton(DEFAULT_PORT, DEFAULT_RECONNECTION_DELAY)
{
        layout = new XMLLayout();
        memset(zeroBuffer, 0, MAX_EVENT_LEN);
}

XMLSocketAppender::XMLSocketAppender(unsigned long address, int port)
: SocketAppenderSkeleton(address, port, DEFAULT_RECONNECTION_DELAY)
{
        layout = new XMLLayout();
        memset(zeroBuffer, 0, MAX_EVENT_LEN);
        connect();
}

XMLSocketAppender::XMLSocketAppender(const LogString& host, int port)
: SocketAppenderSkeleton(host, port, DEFAULT_RECONNECTION_DELAY)
{
        layout = new XMLLayout();
        memset(zeroBuffer, 0, MAX_EVENT_LEN);
        connect();
}

XMLSocketAppender::~XMLSocketAppender() {
}


void XMLSocketAppender::setLocationInfo(bool locationInfo) {
        this->locationInfo = locationInfo;
        XMLLayoutPtr xmlLayout = layout;
        xmlLayout->setLocationInfo(locationInfo);
}


void XMLSocketAppender::renderEvent(const spi::LoggingEventPtr& event,
    helpers::SocketOutputStreamPtr& os, apr_pool_t* p)
{
        LogString output;

        layout->format(output, event, p);

//      TODO
//
//      USES_CONVERSION;
//      os->write((void *)T2A(sz.c_str()), sz.length());
}

void XMLSocketAppender::setOption(const LogString& option,
      const LogString& value) {
        SocketAppenderSkeleton::setOption(option, value, DEFAULT_PORT, DEFAULT_RECONNECTION_DELAY);
}

