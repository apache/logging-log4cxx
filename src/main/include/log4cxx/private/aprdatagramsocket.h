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
#ifndef LOG4CXX_HELPERS_APRDATAGRAM_SOCKET_H
#define LOG4CXX_HELPERS_APRDATAGRAM_SOCKET_H

#include <log4cxx/helpers/datagramsocket.h>

namespace log4cxx
{
namespace helpers
{

class APRDatagramSocket : public DatagramSocket {
    private:
        struct APRDatagramSocketPriv;

    public:
	APRDatagramSocket();

	APRDatagramSocket(int port);

	APRDatagramSocket(int port, InetAddressPtr laddr);

	virtual void bind(int lport, InetAddressPtr laddress);

	void close() override;

	virtual bool isClosed() const;

	/**  Receives a datagram packet from this socket. */
	virtual void receive(DatagramPacketPtr& p);

	/** Sends a datagram packet from this socket. */
	virtual void  send(DatagramPacketPtr& p);

	virtual void connect(InetAddressPtr address, int port);

    private:
	void init();
};

}
}

#endif /* LOG4CXX_HELPERS_APRDATAGRAM_SOCKET_H */
