/***************************************************************************
                          datagramsocket.cpp  -  class DatagramSocket
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

#include <log4cxx/config.h>

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

#include <log4cxx/helpers/datagrampacket.h>
#include <log4cxx/helpers/datagramsocket.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/socketimpl.h>

using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(DatagramSocket);

DatagramSocket::DatagramSocket()
 : fd(0), port(0), localPort(0)
{
	create();
}

DatagramSocket::DatagramSocket(int localPort)
 : fd(0), port(0), localPort(0)
{
	InetAddress bindAddr;
	bindAddr.address = INADDR_ANY;

	create();
	bind(localPort, bindAddr);
}

DatagramSocket::DatagramSocket(int localPort, InetAddress localAddress)
 : fd(0), port(0), localPort(0)
{
	create();
	bind(localPort, localAddress);
}

DatagramSocket::~DatagramSocket()
{
	try
	{
		close();
	}
	catch(SocketException&)
	{
	}
}

/**  Binds a datagram socket to a local port and address.*/
void DatagramSocket::bind(int localPort, InetAddress localAddress)
{
	struct sockaddr_in server_addr;
	int server_len = sizeof(server_addr);

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(localAddress.address);
	server_addr.sin_port = htons(localPort);

	if (::bind(fd, (sockaddr *)&server_addr, server_len) == -1)
	{
		throw BindException();
	}

	this->localPort = localPort;
	this->localAddress = localAddress;
}

/** Close the socket.*/
void DatagramSocket::close()
{
	if (fd != 0)
	{
		LOGLOG_DEBUG(_T("closing socket"));
#ifdef WIN32
		if (::closesocket(fd) == -1)
#else
		if (::close(fd) == -1)
#endif
		{
			throw SocketException();
		}

		fd = 0;
		localPort = 0;
	}
}

void DatagramSocket::connect(InetAddress address, int port)
{
	sockaddr_in client_addr;
	int client_len = sizeof(client_addr);

	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htonl(address.address);
	client_addr.sin_port = htons(port);

	if (::connect(fd, (sockaddr *)&client_addr, client_len) == -1)
	{
		throw ConnectException();
	}

	this->address = address;
	this->port = port;
}

/** Creates a datagram socket.*/
void DatagramSocket::create()
{
	if ((fd = ::socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		throw SocketException();
	}
}

/** Receive the datagram packet.*/
void DatagramSocket::receive(DatagramPacketPtr& p)
{
	sockaddr_in addr;
	int addr_len = sizeof(addr);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(p->getAddress().address);
	addr.sin_port = htons(p->getPort());

#ifdef WIN32
	if (::recvfrom(fd, (char *)p->getData(), p->getLength(), 0,
		(sockaddr *)&addr, &addr_len) == -1)
#else
	if (::recvfrom(fd, p->getData(), p->getLength(), 0,
		(sockaddr *)&addr, (socklen_t *)&addr_len) == -1)
#endif
	{
		throw IOException();
	}

}

/**  Sends a datagram packet.*/
void DatagramSocket::send(DatagramPacketPtr& p)
{
	sockaddr_in addr;
	int addr_len = sizeof(addr);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(p->getAddress().address);
	addr.sin_port = htons(p->getPort());

#ifdef WIN32
	if (::sendto(fd, (const char *)p->getData(), p->getLength(), 0,
		(sockaddr *)&addr, addr_len) == -1)
#else
	if (::sendto(fd, p->getData(), p->getLength(), 0,
		(sockaddr *)&addr, addr_len) == -1)
#endif
	{
		throw IOException();
	}
}



