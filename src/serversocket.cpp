/***************************************************************************
                          serversocket.cpp  -  ServerSocket
                             -------------------
    begin                : ven mai 9 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <log4cxx/config.h>

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <netinet/in.h>
#endif

#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/helpers/socket.h>

#include <assert.h>

using namespace log4cxx::helpers;
 
/**  Creates a server socket on a specified port.
*/
ServerSocket::ServerSocket(int port)
{
	InetAddress bindAddr;
	bindAddr.address = INADDR_ANY;

	socketImpl = new SocketImpl();
	socketImpl->create(true);
	socketImpl->bind(bindAddr, port);
	socketImpl->listen(50);
}

/** Creates a server socket and binds it to the specified local
port number, with the specified backlog.
*/
ServerSocket::ServerSocket(int port, int backlog)
{
	InetAddress bindAddr;
	bindAddr.address = INADDR_ANY;

	socketImpl = new SocketImpl();
	socketImpl->create(true);
	socketImpl->bind(bindAddr, port);
	socketImpl->listen(backlog);
}

/** Create a server with the specified port, listen backlog,
and local IP address to bind to.
*/
ServerSocket::ServerSocket(int port, int backlog, InetAddress bindAddr)
{
	socketImpl = new SocketImpl();
	socketImpl->create(true);
	socketImpl->bind(bindAddr, port);
	socketImpl->listen(backlog);
}

ServerSocket::~ServerSocket()
{
}

/** Listens for a connection to be made to this socket and
accepts it
*/
SocketPtr ServerSocket::accept()
{
	SocketImplPtr accepted = new SocketImpl;
	socketImpl->accept(accepted);
	return new Socket(accepted);
}

/** Retrive setting for SO_TIMEOUT.
*/
int ServerSocket::getSoTimeout() const
{
	return socketImpl->getSoTimeout();
}

/** Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
*/
void ServerSocket::setSoTimeout(int timeout)
{
	socketImpl->setSoTimeout(timeout);
}

