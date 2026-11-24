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

#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/private/serversocket_priv.h>
#include <log4cxx/private/aprserversocket.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ServerSocket)

/**  Creates a server socket on a specified port.
*/
ServerSocket::ServerSocket(std::unique_ptr<ServerSocketPrivate> priv) :
	m_priv(std::move(priv))
{
}

ServerSocket::~ServerSocket()
{
}

void ServerSocket::setAttributes(int localPort, const LogString& localAddress)
{
	m_priv->port = localPort;
	m_priv->hostname = localAddress;
}

/** Retrive setting for SO_TIMEOUT.
*/
int ServerSocket::getSoTimeout() const
{
	return m_priv->timeout;
}

/** Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
*/
void ServerSocket::setSoTimeout(int newVal)
{
	m_priv->timeout = newVal;
}

void ServerSocket::setReuseAddress(bool newValue)
{
	m_priv->reuseAddress = newValue;
}

bool ServerSocket::getReuseAddress()
{
	return m_priv->reuseAddress;
}

ServerSocketUniquePtr ServerSocket::create
	( int              port
	, const LogString& hostname
	, const LogString& className
	)
{
	if (!className.empty())
	{
		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("Desired ") + ServerSocket::getStaticClass().getName()
				+ LOG4CXX_STR(" sub-class: [") + className + LOG4CXX_STR("]"));
		}
		auto& classObj = Loader::loadClass(className);
		auto newObject = classObj.newInstance();
		auto pSocket = dynamic_cast<ServerSocket*>(newObject);
		if (!pSocket)
		{
			LogLog::error(className + LOG4CXX_STR(" is not a ") + ServerSocket::getStaticClass().getName() + LOG4CXX_STR(" sub-class"));
			delete newObject;
		}
		else
		{
			auto result = std::unique_ptr<ServerSocket>(pSocket);
			result->setAttributes(port, hostname);
			return result;
		}
	}
	auto result = std::make_unique<APRServerSocket>();
	result->setAttributes(port, hostname);
	return result;
}
