/***************************************************************************
                          serversocket.h  -  class ServerSocker
                             -------------------
    begin                : ven mai 9 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_HELPERS_SERVER_SOCKET_H
#define _LOG4CXX_HELPERS_SERVER_SOCKET_H

#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT ServerSocket
		{
		public:
			/**  Creates a server socket on a specified port.
			*/
			ServerSocket(int port);

			/** Creates a server socket and binds it to the specified local
			port number, with the specified backlog.
			*/
			ServerSocket(int port, int backlog);

			/** Create a server with the specified port, listen backlog,

			and local IP address to bind to.
			*/
			ServerSocket(int port, int backlog, InetAddress bindAddr);

			~ServerSocket();

			/** Listens for a connection to be made to this socket and
			accepts it
			*/
			SocketPtr accept();

			/** Closes this socket.
			*/
			inline void close()
				{ socketImpl->close(); }

			/** Returns the local address of this server socket.
			*/
			inline InetAddress getInetAddress() const
				{ return socketImpl->getInetAddress(); }

			/** Returns the port on which this socket is listening.
			*/
			inline int getLocalPort() const
				{ return socketImpl->getLocalPort(); }

			/** Returns the implementation address and implementation
			port of this socket as a String
			*/
			inline String toString() const
				{ return socketImpl->toString(); }

			/** Retrive setting for SO_TIMEOUT.
			*/
			int getSoTimeout() const;

			/** Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
			*/
			void setSoTimeout(int timeout);

		protected:
			SocketImplPtr socketImpl;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPERS_SERVER_SOCKET_H
