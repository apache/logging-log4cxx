/***************************************************************************
                          datagramsocket.h  -  class DatagramSocket
                             -------------------
    begin                : 2003/08/02
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

#ifndef _LOG4CXX_HELPERS_DATAGRAM_SOCKET_H
#define _LOG4CXX_HELPERS_DATAGRAM_SOCKET_H

#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/inetaddress.h>

namespace log4cxx
{
	namespace helpers
	{
		class DatagramPacket;
		typedef helpers::ObjectPtrT<DatagramPacket> DatagramPacketPtr;

		class DatagramSocket;
		typedef helpers::ObjectPtrT<DatagramSocket> DatagramSocketPtr;

		/** This class represents a socket for sending and receiving
		datagram packets.*/
		class DatagramSocket : public helpers::ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(DatagramSocket)
			BEGIN_LOG4CXX_INTERFACE_MAP()
				LOG4CXX_INTERFACE_ENTRY(DatagramSocket)
			END_LOG4CXX_INTERFACE_MAP()

			/** Constructs a datagram socket and binds it to any available port
			on the local host machine.*/
			DatagramSocket();

			/** Constructs a datagram socket and binds it to the specified
			port on the local host machine. */
			DatagramSocket(int port);

			/**  Creates a datagram socket, bound to the specified local
			address. */
			DatagramSocket(int port, InetAddress laddr);

			/** ensure the socket is closed. */
			~DatagramSocket();

			/**  Binds a datagram socket to a local port and address.*/
			void bind(int lport, InetAddress laddress);

			/** Creates a datagram socket.*/
			void create();

			/** Closes this datagram socket */
			void close();

			/** Connects the socket to a remote address for this socket. */
			void connect(InetAddress address, int port);

			/** Returns the address to which this socket is connected. */
			inline InetAddress getInetAddress() const
				{ return address; }

			/** Gets the local address to which the socket is bound. */
			inline InetAddress getLocalAddress() const
				{ return localAddress; }

			/**  Returns the port number on the local host to which this
			socket is bound. */
			inline int getLocalPort() const
				{ return localPort; }

			/** Returns the port for this socket */
			inline int getPort() const
				{ return port; }

			/** Returns the binding state of the socket. **/
			inline bool isBound() const
				{ return localPort != 0; }

			/** Returns wether the socket is closed or not. */
			inline bool isClosed() const
				{ return fd != 0; }

			/** Returns the connection state of the socket. */
			inline bool isConnected() const
				{ return port != 0; }

			/**  Receives a datagram packet from this socket. */
			void receive(DatagramPacketPtr p);

			/** Sends a datagram packet from this socket. */
			void  send(DatagramPacketPtr p);

		protected:
			/** The file descriptor object for this socket. */
			int fd;

			InetAddress address;
			InetAddress localAddress;
			int port;

			/** The local port number to which this socket is connected. */
			int localPort;

		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPERS_DATAGRAM_SOCKET_H
