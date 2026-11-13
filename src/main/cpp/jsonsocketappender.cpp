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

#include <log4cxx/net/jsonsocketappender.h>
#include <log4cxx/private/socketappenderskeleton_priv.h>
#include <log4cxx/jsonlayout.h>

namespace
{
// The default port number of remote logging server
int DEFAULT_PORT                 = 5170;

// The default reconnection delay in milliseconds (30 seconds).
int DEFAULT_RECONNECTION_DELAY   = 30000;

} // namespace

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::net;


IMPLEMENT_LOG4CXX_OBJECT(JSONSocketAppender)

#define _priv static_cast<SocketAppenderSkeletonPriv*>(m_priv.get())


JSONSocketAppender::JSONSocketAppender()
	: SocketAppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(DEFAULT_PORT, DEFAULT_RECONNECTION_DELAY))
{
	_priv->layout = std::make_shared<JSONLayout>();
}

JSONSocketAppender::JSONSocketAppender(const helpers::InetAddressPtr& address, int port)
	: SocketAppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(address, port, DEFAULT_RECONNECTION_DELAY))
{
	_priv->layout = std::make_shared<JSONLayout>();
	activateOptions();
}

JSONSocketAppender::JSONSocketAppender(const LogString& host, int port)
	: SocketAppenderSkeleton(std::make_unique<SocketAppenderSkeletonPriv>(host, port, DEFAULT_RECONNECTION_DELAY))
{
	_priv->layout = std::make_shared<JSONLayout>();
	activateOptions();
}

JSONSocketAppender::~JSONSocketAppender()
{
}

int JSONSocketAppender::getDefaultDelay() const
{
	return DEFAULT_RECONNECTION_DELAY;
}

int JSONSocketAppender::getDefaultPort() const
{
	return DEFAULT_PORT;
}





