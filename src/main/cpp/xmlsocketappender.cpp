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

#include <log4cxx/net/xmlsocketappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/bytearrayoutputstream.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/charsetencoder.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/transform.h>
#include <apr_time.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/helpers/transcoder.h>

#if APR_HAS_THREADS

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
#if !LOG4CXX_LOGCHAR_IS_UTF8
    , utf8Encoder(CharsetEncoder::getUTF8Encoder())
#endif
{
        layout = new XMLLayout();
}

XMLSocketAppender::XMLSocketAppender(InetAddressPtr address1, int port1)
: SocketAppenderSkeleton(address1, port1, DEFAULT_RECONNECTION_DELAY)
#if !LOG4CXX_LOGCHAR_IS_UTF8
    , utf8Encoder(CharsetEncoder::getUTF8Encoder())
#endif
{
        layout = new XMLLayout();
        connect();
}

XMLSocketAppender::XMLSocketAppender(const LogString& host, int port1)
: SocketAppenderSkeleton(host, port1, DEFAULT_RECONNECTION_DELAY)
#if !LOG4CXX_LOGCHAR_IS_UTF8
    , utf8Encoder(CharsetEncoder::getUTF8Encoder())
#endif
{
        layout = new XMLLayout();
        connect();
}

XMLSocketAppender::~XMLSocketAppender() {
    finalize();
}


void XMLSocketAppender::setLocationInfo(bool locationInfo1) {
        this->locationInfo = locationInfo1;
        XMLLayoutPtr xmlLayout(layout);
        xmlLayout->setLocationInfo(locationInfo1);
}


void XMLSocketAppender::renderEvent(const spi::LoggingEventPtr& event,
    const helpers::OutputStreamPtr& os1, Pool& p)
{
        LogString output;
        layout->format(output, event, p);
#if LOG4CXX_LOGCHAR_IS_UTF8
        ByteBuffer buf(const_cast<char*>(output.data()), output.size());
#else
        size_t maxSize = output.size() * 6;
        char* bytes = (char*) apr_palloc((apr_pool_t*) p.getAPRPool(), maxSize);
        ByteBuffer buf(bytes, maxSize);
        LogString::const_iterator iter(output.begin());
        utf8Encoder->encode(output, iter, buf);
        buf.flip();  
#endif
        os1->write(buf, p);
}

void XMLSocketAppender::setOption(const LogString& option,
      const LogString& value) {
        SocketAppenderSkeleton::setOption(option, value, DEFAULT_PORT, DEFAULT_RECONNECTION_DELAY);
}

#endif

