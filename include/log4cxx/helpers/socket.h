/***************************************************************************
                          socket.h  -  class Socket
                             -------------------
    begin                : jeu mai 8 2003
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

#ifndef _LOG4CXX_HELPERS_SOCKET_H
#define _LOG4CXX_HELPERS_SOCKET_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/socketimpl.h>

namespace log4cxx
{
	namespace helpers
	{
		class ServerSocker;
		
		class Socket;
		typedef helpers::ObjectPtrT<Socket> SocketPtr;

		class SocketOutputStream;
		typedef helpers::ObjectPtrT<SocketOutputStream> SocketOutputStreamPtr;

		class SocketInputStream;
		typedef helpers::ObjectPtrT<SocketInputStream> SocketInputStreamPtr;

		/**
		<p>This class implements client sockets (also called just "sockets"). A socket
		is an endpoint for communication between two machines.
		<p>The actual work of the socket is performed by an instance of the SocketImpl
		class. An application, by changing the socket factory that creates the socket
		implementation, can configure itself to create sockets appropriate to the 
		local firewall.
		*/
		class Socket : public helpers::ObjectImpl
		{
		friend class ServerSocket;
		protected:
			/** Creates an unconnected socket.
			*/
			Socket();

		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(Socket)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(Socket)
			END_LOG4CXX_CAST_MAP()

			/** Creates a stream socket and connects it to the specified port
			number at the specified IP address.
			*/
			Socket(InetAddress address, int port);

			/** Creates a socket and connects it to the specified remote
			address on the specified remote port.
			*/
			Socket(InetAddress address, int port,
				InetAddress localAddr, int localPort);

		protected:
			/** Creates an unconnected Socket
			with a user-specified SocketImpl.
			*/
			Socket(SocketImplPtr impl);

		public:
			/** Creates a stream socket and connects it to the specified
			port number on the named host.
			*/
			Socket(const tstring& host, int port);

			/**  Creates a socket and connects it to the specified remote
			host on the specified remote port.
			*/
			Socket(const tstring& host, int port,
				InetAddress localAddr, int localPort);

			size_t read(void * buf, size_t len)
				{ return socketImpl->read(buf, len); }

			size_t write(const void * buf, size_t len)
				{ return socketImpl->write(buf, len); }

			/** Closes this socket. */
			void close()
				{ socketImpl->close(); }

			/** Returns the value of this socket's address field. */
			inline InetAddress getInetAddress() const
				{ return socketImpl->getInetAddress(); }

			/** Returns the value of this socket's localport field. */
			inline int getLocalPort() const
				{ return socketImpl->getLocalPort(); }

			/** Returns the value of this socket's port field. */
			inline int getPort() const
				{ return socketImpl->getPort(); }

			/**  Returns an output stream for this socket. */
			SocketOutputStreamPtr getOutputStream();

			/**  Returns an input stream for this socket. */
			SocketInputStreamPtr getInputStream();

  protected:
			SocketImplPtr socketImpl;
		};
	} // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SOCKET_H
