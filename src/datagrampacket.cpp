/***************************************************************************
                          datagrampacket.cpp  -  class DatagramPacket
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

#include <log4cxx/helpers/datagrampacket.h>

using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(DatagramPacket);

/** Constructs a DatagramPacket for receiving packets of length
<code>length</code>. */
DatagramPacket::DatagramPacket(void * buf, int length)
: buf(buf), offset(0), length(length), port(0)
{
}

/** Constructs a datagram packet for sending packets of length
<code>length/<code> to the specified port number on the specified
host. */
DatagramPacket::DatagramPacket(void * buf, int length, InetAddress address,
int port)
: buf(buf), offset(0), length(length), address(address), port(port)
{
}

/** Constructs a DatagramPacket for receiving packets of length
<code>length</code>, specifying an offset into the buffer. */
DatagramPacket::DatagramPacket(void * buf, int offset, int length)
: buf(buf), offset(offset), length(length), port(0)
{
}
/** Constructs a datagram packet for sending packets of length
<code>length</code> with offset <code>offset</code> to the
specified port number on the specified host. */
DatagramPacket::DatagramPacket(void * buf, int offset, int length,
InetAddress address, int port)
: buf(buf), offset(offset), length(length), address(address), port(port)
{
}

DatagramPacket::~DatagramPacket()
{
}
