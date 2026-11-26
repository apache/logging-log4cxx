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

#ifndef LOG4CXX_HELPERS_SOCKET_PRIV_H
#define LOG4CXX_HELPERS_SOCKET_PRIV_H

#include <log4cxx/helpers/datagramsocket.h>

namespace LOG4CXX_NS
{
namespace helpers
{

struct DatagramSocket::DatagramSocketPriv
{
	virtual ~DatagramSocketPriv() = default;

	/** The network to use - set by bind()
	*/
	InetAddressPtr localAddress;

	/** The local port number - set by bind()
	*/
	int localPort{ 0 };

	/** The remote address - set by connect()
	*/
	InetAddressPtr address;

	/** The remote port - set by connect()
	*/
	int port{ 0 };
};

}
}

#endif /* LOG4CXX_HELPERS_SOCKET_PRIV_H */
