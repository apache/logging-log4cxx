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
#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/private/socketappenderskeleton_priv.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::net;


IMPLEMENT_LOG4CXX_OBJECT(XMLSocketAppender)

#define _priv static_cast<SocketAppenderSkeletonPriv*>(m_priv.get())

// The default port number of remote logging server (4560)
int XMLSocketAppender::DEFAULT_PORT                 = 4560;

// The default reconnection delay (30000 milliseconds or 30 seconds).
int XMLSocketAppender::DEFAULT_RECONNECTION_DELAY   = 30000;


XMLSocketAppender::XMLSocketAppender()
	: SocketAppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(DEFAULT_PORT, DEFAULT_RECONNECTION_DELAY))
{
	_priv->layout = std::make_shared<xml::XMLLayout>();
}

XMLSocketAppender::XMLSocketAppender(const helpers::InetAddressPtr& address1, int port1)
	: SocketAppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(address1, port1, DEFAULT_RECONNECTION_DELAY))
{
	_priv->layout = std::make_shared<xml::XMLLayout>();
	activateOptions();
}

XMLSocketAppender::XMLSocketAppender(const LogString& host, int port1)
	: SocketAppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(host, port1, DEFAULT_RECONNECTION_DELAY))
{
	_priv->layout = std::make_shared<xml::XMLLayout>();
	activateOptions();
}

XMLSocketAppender::~XMLSocketAppender()
{
}


int XMLSocketAppender::getDefaultDelay() const
{
	return DEFAULT_RECONNECTION_DELAY;
}

int XMLSocketAppender::getDefaultPort() const
{
	return DEFAULT_PORT;
}


void XMLSocketAppender::append( LOG4CXX_APPEND_FORMAL_PARAMETERS )
{
	if (_priv->outputSink)
	{
		LogString output;
		_priv->layout->format(output, event);

		try
		{
			_priv->outputSink->write(output);
			_priv->outputSink->flush();
		}
		catch (std::exception& e)
		{
			_priv->outputSink.reset();
			helpers::LogLog::warn(LOG4CXX_STR("Detected problem with connection: "), e);

			if (getReconnectionDelay() > 0)
			{
				_priv->fireConnector();
			}
		}
	}
}




