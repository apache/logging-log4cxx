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
#ifndef LOG4CXX_SOCKETAPPENDERSKELETON_PRIVATE_H
#define LOG4CXX_SOCKETAPPENDERSKELETON_PRIVATE_H

#include <log4cxx/net/socketappenderskeleton.h>
#include <log4cxx/private/appenderskeleton_priv.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/helpers/writer.h>

namespace LOG4CXX_NS
{
namespace net
{

struct SocketAppenderSkeleton::SocketAppenderSkeletonPriv : public AppenderSkeletonPrivate
{
	SocketAppenderSkeletonPriv(int defaultPort, int reconnectionDelay) :
		AppenderSkeletonPrivate(),
		remoteHost(),
		address(),
		port(defaultPort),
		reconnectionDelay(reconnectionDelay),
		locationInfo(false)
        { }

	SocketAppenderSkeletonPriv(const helpers::InetAddressPtr& address, int defaultPort, int reconnectionDelay) :
		AppenderSkeletonPrivate(),
		remoteHost(),
		address(address),
		port(defaultPort),
		reconnectionDelay(reconnectionDelay),
		locationInfo(false)
        { }

	SocketAppenderSkeletonPriv(const LogString& host, int port, int delay) :
		AppenderSkeletonPrivate(),
		remoteHost(host),
		address(helpers::InetAddress::getByName(host)),
		port(port),
		reconnectionDelay(delay),
		locationInfo(false)
	{ }

	~SocketAppenderSkeletonPriv()
	{
		if (this->setClosed())
			this->close();
	}

	/**
	host name
	*/
	LogString remoteHost;

	/**
	IP address
	*/
	helpers::InetAddressPtr address;

	int port;
	int reconnectionDelay;
	bool locationInfo;
	void close();

	/**
	Manages asynchronous reconnection attempts.
	*/
	helpers::ThreadUtility::ManagerWeakPtr taskManager;

	/**
	The reconnection task name.
	*/
	LogString taskName;

	/**
	The sink for formatted logging events.
	*/
	helpers::WriterPtr outputSink;

	void connect();

	void fireConnector();

	void setOutputSink(const helpers::SocketPtr& socket);

	void retryConnect();

};

} // namespace net
} // namespace log4cxx

#endif /* LOG4CXX_SOCKETAPPENDERSKELETON_PRIVATE_H */
