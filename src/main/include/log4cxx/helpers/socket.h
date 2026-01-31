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

#ifndef _LOG4CXX_HELPERS_SOCKET_H
#define _LOG4CXX_HELPERS_SOCKET_H

#include <log4cxx/helpers/inetaddress.h>
#include <log4cxx/helpers/pool.h>


namespace LOG4CXX_NS
{
namespace helpers
{
class ByteBuffer;

class Socket;
LOG4CXX_PTR_DEF(Socket);
LOG4CXX_UNIQUE_PTR_DEF(Socket);

/**
Abstract base class for an outgoing socket connection.
A socket is an endpoint for communication between
two network connected machines or processes.
*/
class LOG4CXX_EXPORT Socket : public helpers::Object
{
	protected:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(SocketPrivate, m_priv)
		Socket(LOG4CXX_PRIVATE_PTR(SocketPrivate) priv);

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Socket)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Socket)
		END_LOG4CXX_CAST_MAP()

		virtual ~Socket();

		virtual size_t write(ByteBuffer&) = 0;

#if 15 < LOG4CXX_ABI_VERSION
		/**
		Use \c newValue for the behaviour when the network buffer (on an accepted socket connection) is full.

		When true, an exception is thrown if the write would block.
		*/
		virtual void setNonBlocking(bool newValue) = 0;
#endif

		/** Close this socket. */
		virtual void close() = 0;

		/** Returns the value of this socket's address field. */
		InetAddressPtr getInetAddress() const;

		/** Returns the value of this socket's port field. */
		int getPort() const;

		/** Create a concrete instance of this class
		*/
		static SocketUniquePtr create(InetAddressPtr& address, int port);

	private:
		Socket(const Socket&);
		Socket& operator=(const Socket&);

};

} // namespace helpers
} // namespace log4cxx

#if 15 < LOG4CXX_ABI_VERSION
#define LOG4CXX_16_VIRTUAL_SPECIFIER override
#else
#define LOG4CXX_16_VIRTUAL_SPECIFIER
#endif

#endif // _LOG4CXX_HELPERS_SOCKET_H
