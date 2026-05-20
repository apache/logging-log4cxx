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
#include <log4cxx/helpers/socket.h>
#include <log4cxx/private/socket_priv.h>
#include <log4cxx/private/aprsocket.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/loglog.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(Socket)

Socket::Socket(std::unique_ptr<Socket::SocketPrivate> priv) :
	m_priv(std::move(priv)){

}

Socket::~Socket()
{
}

InetAddressPtr Socket::getInetAddress() const
{
	return m_priv->address;
}

int Socket::getPort() const
{
	return m_priv->port;
}

void Socket::setAttributes(const InetAddressPtr& newAddress, int newPort)
{
	m_priv->address = newAddress;
	m_priv->port = newPort;
}

#if LOG4CXX_ABI_VERSION <= 15
SocketUniquePtr Socket::create(InetAddressPtr& address, int port){
	return std::make_unique<APRSocket>(address, port);
}
#endif

SocketUniquePtr Socket::create(LOG4CXX_16_CONST InetAddressPtr& address, int port, const LogString& concreteClassName)
{
#if 15 < LOG4CXX_ABI_VERSION
	if (!concreteClassName.empty())
	{
		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("Desired ") + Socket::getStaticClass().getName()
				+ LOG4CXX_STR(" sub-class: [") + concreteClassName + LOG4CXX_STR("]"));
		}
		auto& classObj = Loader::loadClass(concreteClassName);
		auto newObject = classObj.newInstance();
		auto pSocket = dynamic_cast<Socket*>(newObject);
		if (!pSocket)
		{
			LogLog::error(concreteClassName + LOG4CXX_STR(" is not a ") + Socket::getStaticClass().getName() + LOG4CXX_STR(" sub-class"));
			delete newObject;
		}
		else
		{
			auto result = std::unique_ptr<Socket>(pSocket);
			pSocket->setAttributes(address, port);
			pSocket->open();
			return result;
		}
	}
#endif
	return std::make_unique<APRSocket>(address, port);
}

