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

#ifndef _LOG4CXX_HELPERS_SERVER_SOCKET_H
#define _LOG4CXX_HELPERS_SERVER_SOCKET_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/socket.h>

namespace LOG4CXX_NS
{
namespace helpers
{

class ServerSocket;
LOG4CXX_PTR_DEF(ServerSocket);
LOG4CXX_UNIQUE_PTR_DEF(ServerSocket);

class LOG4CXX_EXPORT ServerSocket : public Object
{
	protected:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(ServerSocketPrivate, m_priv)
		ServerSocket(LOG4CXX_PRIVATE_PTR(ServerSocketPrivate) priv);

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(ServerSocket)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(ServerSocket)
		END_LOG4CXX_CAST_MAP()

		virtual ~ServerSocket();

		/**  Use \c localPort and the network at \c localAddress when accepting connections.
		*/
		virtual void setAttributes(int localPort, const LogString& localAddress = {});

		/** Listen for a connection to be made to this socket
		*/
		virtual SocketPtr accept() = 0;

		/** Is this available for use?
		*/
		virtual bool is_open() = 0;

		/** Prepare the socket to accept incoming network connections.
		*/
		virtual void open() = 0;

		/** Stop accepting incoming network connections.
		*/
		virtual void close() = 0;

		/** Retrive setting for SO_TIMEOUT.
		*/
		int getSoTimeout() const;

		/** Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
		*/
		void setSoTimeout(int timeout);

		/** The value of the SO_REUSEADDR attribute.
		*/
		bool getReuseAddress();

		/** Use \c newValue for the SO_REUSEADDR attribute.
		*/
		void setReuseAddress(bool newValue);

		/**  A \c className type socket, that will listen on \c localPort on the network at \c localAddress.
		If \c className is empty, a APRServerSocket is returned.
		*/
		static ServerSocketUniquePtr create
			( int              localPort
			, const LogString& localAddress = {}
			, const LogString& className = {}
			);

};
}  // namespace helpers
} // namespace log4cxx

#endif //_LOG4CXX_HELPERS_SERVER_SOCKET_H
