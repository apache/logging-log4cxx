/***************************************************************************
                          socket.cpp  -  description
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

#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/socketinputstream.h>

#ifdef WIN32
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <string.h>

using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(Socket)

/** Creates an unconnected socket.
*/
Socket::Socket()
{
}

/** Creates a stream socket and connects it to the specified port
number at the specified IP address.
*/
Socket::Socket(InetAddress address, int port)
{
	socketImpl = new SocketImpl();
	socketImpl->create(true);
	socketImpl->connect(address, port);
}

/** Creates a socket and connects it to the specified remote
address on the specified remote port.
*/
Socket::Socket(InetAddress address, int port,
	InetAddress localAddr, int localPort)
{
	socketImpl = new SocketImpl();
	socketImpl->create(true);
	socketImpl->connect(address, port);
	socketImpl->bind(localAddr, localPort);
}

/** Creates an unconnected Socket
with a user-specified SocketImpl.
*/
Socket::Socket(SocketImplPtr impl) : socketImpl(impl)
{
}


/** Creates a stream socket and connects it to the specified
port number on the named host.
*/
Socket::Socket(const String& host, int port)
{
	socketImpl = new SocketImpl();
	socketImpl->create(true);
	socketImpl->connect(host, port);
}

/**  Creates a socket and connects it to the specified remote
host on the specified remote port.
*/
Socket::Socket(const String& host, int port,
	InetAddress localAddr, int localPort)
{
	socketImpl = new SocketImpl();
	socketImpl->create(true);
	socketImpl->connect(host, port);
	socketImpl->bind(localAddr, localPort);
}

/**  Returns an output stream for this socket. */
SocketOutputStreamPtr Socket::getOutputStream()
{
	return new SocketOutputStream(this);
}

/**  Returns an input stream for this socket. */
SocketInputStreamPtr Socket::getInputStream()
{
	return new SocketInputStream(this);
}


