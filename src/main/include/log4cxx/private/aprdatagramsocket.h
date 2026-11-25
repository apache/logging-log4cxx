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

namespace LOG4CXX_NS
{
namespace helpers
{

class APRDatagramSocket : public DatagramSocket
{
private:
	struct APRDatagramSocketPriv;

public:
	APRDatagramSocket();
	~APRDatagramSocket();

	/// Has #bind succeeded?
	bool isBound() const override;

	/// Has #connect succeeded?
	bool isConnected() const override;

	/// Prepare to listen on a local port and network.
	void bind(int lport, const InetAddressPtr& laddress) override;

	/// Make this socket unusable.
	void close() override;

	/// Receive the bytes of a datagram packet into the \c p.getLength() sized buffer at \c p.getData().
	void receive(DatagramPacket& p) override;

	/// Send \c p from this socket.
	void send(const DatagramPacket& p) override;

	/// Prepare this socket for messages to the remote system at \c address.
	void connect(const InetAddressPtr& address, int port) override;
};

}
}

#endif /* LOG4CXX_HELPERS_APRDATAGRAM_SOCKET_H */
