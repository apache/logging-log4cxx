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
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/datagramsocket.h>
#include <log4cxx/helpers/datagrampacket.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/private/datagramsocket_priv.h>
#include <log4cxx/private/aprdatagramsocket.h>

using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(DatagramSocket)

DatagramSocket::DatagramSocket(std::unique_ptr<DatagramSocketPriv> priv) :
	m_priv(std::move(priv))
{}

DatagramSocket::~DatagramSocket()
{
	try
	{
		close();
	}
	catch (const SocketException&)
	{
	}
}

/** Close the socket.*/
void DatagramSocket::close()
{
}

InetAddressPtr DatagramSocket::getInetAddress() const
{
	return m_priv->address;
}

InetAddressPtr DatagramSocket::getLocalAddress() const
{
	return m_priv->localAddress;
}

int DatagramSocket::getLocalPort() const
{
	return m_priv->localPort;
}

int DatagramSocket::getPort() const
{
	return m_priv->port;
}

DatagramSocketUniquePtr DatagramSocket::create
	( int                   localPort
	, const InetAddressPtr& localAddress
	, const LogString&      className
	)
{
	if (!className.empty())
	{
		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("Desired ") + DatagramSocket::getStaticClass().getName()
				+ LOG4CXX_STR(" sub-class: [") + className + LOG4CXX_STR("]"));
		}
		auto& classObj = Loader::loadClass(className);
		auto newObject = classObj.newInstance();
		auto pSocket = dynamic_cast<DatagramSocket*>(newObject);
		if (!pSocket)
		{
			LogLog::error(className + LOG4CXX_STR(" is not a ") + DatagramSocket::getStaticClass().getName() + LOG4CXX_STR(" sub-class"));
			delete newObject;
		}
		else
		{
			auto result = std::unique_ptr<DatagramSocket>(pSocket);
			if (0 < localPort)
				pSocket->bind(localPort, localAddress);
			return result;
		}
	}
	auto sock = std::make_unique<APRDatagramSocket>();
	if (0 < localPort)
		sock->bind(localPort, localAddress);
	return sock;
}
