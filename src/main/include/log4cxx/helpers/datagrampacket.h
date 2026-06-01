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

#ifndef _LOG4CXX_HELPERS_DATAGRAM_PACKET
#define _LOG4CXX_HELPERS_DATAGRAM_PACKET

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/inetaddress.h>
#include <cstddef>

namespace LOG4CXX_NS
{
namespace helpers
{

/** This class represents a datagram packet.
<p>Datagram packets are used to implement a connectionless packet
delivery service. Each message is routed from one machine to another
based solely on information contained within that packet. Multiple
packets sent from one machine to another might be routed differently,
and might arrive in any order.
*/
class LOG4CXX_EXPORT DatagramPacket : public helpers::Object
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(DatagramPacketPriv, m_priv)

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(DatagramPacket)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(DatagramPacket)
		END_LOG4CXX_CAST_MAP()

#if LOG4CXX_ABI_VERSION <= 15
		/** Constructs a DatagramPacket for receiving packets of length
		<code>length</code>. */
		DatagramPacket(void* buf, int length);

		/** Constructs a datagram packet for sending packets of length
		<code>length</code> to the specified port number on the specified
		host. */
		DatagramPacket(void* buf, int length, InetAddressPtr address, int port);

		/** Constructs a DatagramPacket for receiving packets of length
		<code>length</code>, specifying an offset into the buffer. */
		DatagramPacket(void* buf, int offset, int length);

		/** Constructs a datagram packet for sending packets of length
		<code>length</code> with offset <code>offset</code> to the
		specified port number on the specified host. */
		DatagramPacket(void* buf, int offset, int length, InetAddressPtr address,
			int port);
#else
		/** Constructs a DatagramPacket for receiving packets of length
		<code>length</code>. */
		DatagramPacket(void* buf, std::size_t length);

		/** Constructs a datagram packet for sending packets of length
		<code>length</code> to the specified port number on the specified
		host. */
		DatagramPacket(void* buf, std::size_t length, InetAddressPtr address, int port);

		/** Constructs a DatagramPacket for receiving packets of length
		<code>length</code>, specifying an offset into the buffer. */
		DatagramPacket(void* buf, std::size_t offset, std::size_t length);

		/** Constructs a datagram packet for sending packets of length
		<code>length</code> with offset <code>offset</code> to the
		specified port number on the specified host. */
		DatagramPacket(void* buf, std::size_t offset, std::size_t length, InetAddressPtr address,
			int port);
#endif

		~DatagramPacket();

		/** Returns the IP address of the machine to which this datagram
		is being sent or from which the datagram was received. */
		InetAddressPtr getAddress() const;

		/** Returns the data received or the data to be sent. */
		void* getData() const;

#if LOG4CXX_ABI_VERSION <= 15
		/** Returns the length of the data to be sent or the length of the
		data received. */
		int getLength() const;

		/** Returns the offset of the data to be sent or the offset of the
		data received. */
		int getOffset() const;
#else
		/** Returns the length of the data to be sent or the length of the
		data received. */
		std::size_t getLength() const;

		/** Returns the offset of the data to be sent or the offset of the
		data received. */
		std::size_t getOffset() const;
#endif

		/** Returns the port number on the remote host to which this
		 datagram is being sent or from which the datagram was received. */
		int getPort() const;

		void setAddress(InetAddressPtr address1);

		/** Set the data buffer for this packet. */
		void setData(void* buf1);

#if LOG4CXX_ABI_VERSION <= 15
		/** Set the data buffer for this packet. */
		void setData(void* buf1, int offset1, int length1);

		/** Set the length for this packet. */
		void setLength(int length1);
#else
		/** Set the data buffer for this packet. */
		void setData(void* buf1, std::size_t offset1, std::size_t length1);

		/** Set the length for this packet. */
		void setLength(std::size_t length1);
#endif

		void setPort(int port1);

	private:
		//
		//  prevent copy and assignment statements
		DatagramPacket(const DatagramPacket&);
		DatagramPacket& operator=(const DatagramPacket&);

}; // class DatagramPacket
LOG4CXX_PTR_DEF(DatagramPacket);
}  // namespace helpers
} // namespace log4cxx

#endif // _LOG4CXX_HELPERS_DATAGRAM_PACKET
