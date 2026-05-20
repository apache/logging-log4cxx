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
#ifndef LOG4CXX_BSD_SOCKET_H_
#define LOG4CXX_BSD_SOCKET_H_
#include <log4cxx/helpers/socket.h>

namespace LOG4CXX_NS::helpers
{

/// A class for writing to a network socket.
class BSDSocket : public Socket
{
public: // Class attributes
	static const int DefaultPort;

public:
	DECLARE_LOG4CXX_OBJECT(BSDSocket)
	BEGIN_LOG4CXX_CAST_MAP()
	LOG4CXX_CAST_ENTRY(Socket)
	LOG4CXX_CAST_ENTRY(BSDSocket)
	END_LOG4CXX_CAST_MAP()

public: // ...structors
	/// A \c isDatagramType connection
	BSDSocket(bool isDatagramType = false, bool ipV6 = false);
	/// A \c isDatagramType connection on \c port to \c address
	BSDSocket(const InetAddressPtr& address, int port = DefaultPort, bool isDatagramType = false, bool ipV6 = false);

	/// Release resources
	~BSDSocket();

public: // Hooked methods
	/// Is this available for use?
	bool is_open() override;

	/// Prepare the socket for use.
	void open() override;

	/// Release resources required by an open socket.
	void close() override;

	/// Send the bytes in \c data.
	size_t write(ByteBuffer& data) override;

	/// Use \c newValue for the behaviour when the network buffer (on an accepted socket connection) is full.
	void setNonBlocking(bool newValue) override;

private: // Class methods
	struct Data;
};

} // namespace LOG4CXX_NS::helpers

#endif // LOG4CXX_BSD_SOCKET_H_
