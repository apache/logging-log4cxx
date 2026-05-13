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
 #include "bsdsocket.h"
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/private/socket_priv.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>
#include <string>
#include <memory>
#ifdef WIN32
#undef UNICODE
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netdb.h>
#include <fcntl.h>
#include <cstring>
#endif
#include <sstream>
#undef min
#include <algorithm>

// Types
using HandleType = int;
using InfoType = struct addrinfo;
using SockAddrType = struct sockaddr_storage;
#ifdef WIN32
using SockSizeType = int;
#else
using SockSizeType = unsigned int;
#endif
using SockAddrPtr = std::unique_ptr<SockAddrType>;

/// Streamable array elements
template <typename T, typename S, typename D = T>
class SeparatedArray
{
	const T *m_vec;
	size_t m_len;
	S m_separator;
	size_t m_perLine;
public:
	SeparatedArray(const T *vec, size_t len, S separ, size_t perLine = 10)
		: m_vec(vec)
		, m_len(len)
		, m_separator(separ)
		, m_perLine(perLine)
	{}
	void Write(std::ostream& os) const
	{
		if (0 < m_perLine && m_perLine <= m_len)
			os << std::endl;
		for (size_t i = 0; i < m_len; ++i)
		{
			if (0 < i)
			{
				if (0 < m_perLine && 0 == (i % m_perLine))
					os << std::endl;
				else
					os << m_separator;
			}
			os << (D)m_vec[i];
		}
	}
};

/// Put \c S separated type \c D elements of \c v onto \c os
	template <typename T, typename S, typename D>
	std::ostream&
 operator<<(std::ostream& os, const SeparatedArray<T, S, D>& v)
{ v.Write(os); return os;  }

/// An overload that puts the internet address in \c data onto \c os
	inline std::ostream&
operator<<(std::ostream& os, const struct sockaddr& data)
{
	if (AF_INET == data.sa_family)
	{
		using Formatter = SeparatedArray<unsigned char, unsigned char, unsigned>;
		const struct sockaddr_in& ipv4Data = reinterpret_cast<const struct sockaddr_in&>(data);
		const unsigned char* octet = (const unsigned char*)&ipv4Data.sin_addr;
		os << std::dec << Formatter(octet, 4, '.') << ':' << ntohs(ipv4Data.sin_port);
	}
	else
	{
		using Formatter = SeparatedArray<unsigned short, unsigned char, unsigned>;
		const struct sockaddr_in6& ipv6Data = reinterpret_cast<const struct sockaddr_in6&>(data);
		const unsigned short* hextet = (const unsigned short*)&ipv6Data.sin6_addr;
		os << '[' << std::hex << Formatter(hextet, 8, ':') << ']';
		os << ':' << std::dec << ntohs(ipv6Data.sin6_port);
	}
	return os;
}

/// An overload that puts the internet address in \c data onto \c os
	inline std::ostream&
operator<<(std::ostream& os, const struct sockaddr_storage& data)
{
	os << reinterpret_cast<const struct sockaddr&>(data);
	return os;
}

namespace
{

class UnexpectedSystemError : public LOG4CXX_NS::helpers::SocketException
{
	using BaseType = LOG4CXX_NS::helpers::SocketException;
public: // ...stuctors
	UnexpectedSystemError(const char* context, const std::string& data = {})
#ifdef WIN32
		: BaseType(MakeMessage(::GetLastError(), context, data))
#else
		: BaseType(MakeMessage(errno, context, data))
#endif
	{ }
	UnexpectedSystemError(int id, const char* context, const std::string& data = {})
		: BaseType(MakeMessage(id, context, data))
	{ }
public: // Class methods
	static LOG4CXX_NS::LogString MakeConnectMessage()
	{
#ifdef WIN32
		return MakeMessage(WSAGetLastError(), "connect");
#else
		return MakeMessage(errno, "connect");
#endif
	}
	static LOG4CXX_NS::LogString MakeMessage(int id, const char* context, const std::string& data = {})
	{
		std::stringstream ss;
		ss << "System error 0x" << std::hex << id << ": " << context;
		if (!data.empty())
			ss << ' ' << data;
		LOG4CXX_DECODE_CHAR(result, ss.str());
		return result;
	}
};

/// An adaptor of message data for printing
class MessageData
{
	const unsigned char *m_vec;
	size_t m_len;
public:
	/// A streamable version of the \c len bytes in \c vec
	MessageData(const void *vec, size_t len)
		: m_vec(reinterpret_cast<const unsigned char *>(vec))
		, m_len(len)
		{}
	void Write(std::ostream& os) const
	{
		for (size_t i = 0; i < m_len; ++i)
		{
			if ('&' == m_vec[i])
				os << "&amp;";
			else if (isprint(m_vec[i]))
				os << m_vec[i];
			else
				os << "&#" << std::hex << int(m_vec[i]) << ';';
		}
	}
};
	std::ostream&
operator<<(std::ostream& s, const MessageData& v)
{ v.Write(s); return s;  }

#ifdef WIN32
class SystemInitialiser
{
public:
	SystemInitialiser()
	{
		WORD version = MAKEWORD(2, 2);
		WSADATA data;
		if (WSAStartup(version, &data) != 0)
		{
			throw UnexpectedSystemError(WSAGetLastError(), "initialising WSA");
		}
	}
};
void CheckWSA()
{
	static SystemInitialiser _;
}
#endif

} // namespace

namespace LOG4CXX_NS::helpers
{

struct BSDSocket::Data : public Socket::SocketPrivate
{
	int m_inetType;                 //!< SOCK_DGRAM or SOCK_STREAM
	int m_inetFamily;               //!< AF_INET or AF_INET6
	InfoType* m_remote{ 0 };        //!< A chain of interfaces on which data may be sent and received
	HandleType m_handle{ -1 };      //!< The handle for send and receive
	SockAddrPtr m_remoteAddress{ std::make_unique<SockAddrType>() };
	SockSizeType m_remoteAddressSize{ 0 };
	LoggerPtr m_log{ Logger::getLogger("BSDSocket") };

	Data(bool isDatagramType = false, bool ipV6 = false)
		: m_inetType{ isDatagramType ? SOCK_DGRAM : SOCK_STREAM }
		, m_inetFamily{ ipV6 ? AF_INET6 : AF_INET }
	{
#ifdef WIN32
		CheckWSA();
#endif
	}

	Data(const InetAddressPtr& address, int port, bool isDatagramType = false, bool ipV6 = false)
		: Socket::SocketPrivate(address, port)
		, m_inetType{ isDatagramType ? SOCK_DGRAM : SOCK_STREAM }
		, m_inetFamily{ ipV6 ? AF_INET6 : AF_INET }
	{
#ifdef WIN32
		CheckWSA();
#endif
	}

	/// Prepare the socket for use.
	void open();

	/// Release resources required by an open socket.
	void close();

	/// Send the bytes in \c data.
	size_t write(ByteBuffer& data);

	/// Initialise the port field of \c addr to \c port
	void setInternetPort(struct sockaddr* addr, int port);

	/// Set up \c m_remote for a \c m_inetType connection on \c port to \c node using \c m_inetFamily
	void setRemote(const InetAddressPtr& address, int port);

	/// Initialise \c m_remoteAddress from \c data
	void setRemoteAddress(const struct sockaddr* data, size_t dataSize);
};

// Prepare the channel for use.
	void
BSDSocket::Data::open()
{
	LOGLOG_DEBUG(m_log, "open:");
	setRemote(this->address, this->port);
	m_handle = (HandleType)socket(m_inetFamily, m_inetType, SOCK_DGRAM == m_inetType ? IPPROTO_UDP : IPPROTO_TCP);
	if (m_handle < 0)
	   throw UnexpectedSystemError("creating socket");

#ifdef WIN32
	// Prevent a WSAECONNRESET when a previous send operation reported a ICMP Port Unreachable message
	// to allow sending when the destination port is not yet receiving data
	static const int SIO_UDP_CONNRESET = _WSAIOW(IOC_VENDOR, 12);
	BOOL bNewBehavior = FALSE;
	DWORD dwBytesReturned = 0;
	WSAIoctl
		( m_handle
		, SIO_UDP_CONNRESET // dwIoControlCode
		, &bNewBehavior // lpvInBuffer
		, sizeof (bNewBehavior) // cbInBuffer
		, NULL // lpvOutBuffer
		, 0 // cbOutBuffer
		, &dwBytesReturned // lpcbBytesReturned
		, NULL // lpOverlapped
		, NULL // lpCompletionRoutine
		);
#endif
	LOGLOG_DEBUG(m_log, "open:"
		<< " connect " << m_handle
		<< " to address " << *m_remoteAddress
		);
	auto rs = connect(m_handle, (const struct sockaddr *)m_remoteAddress.get(), m_remoteAddressSize);
	if (rs < 0)
		throw ConnectException(UnexpectedSystemError::MakeConnectMessage());
	LOGLOG_DEBUG(m_log, "open:" << " handle " << m_handle);
}

// Release resources required by an open channel.
	void
BSDSocket::Data::close()
{
	LOGLOG_DEBUG(m_log, "close:" << " handle " << m_handle);
#ifdef WIN32
	closesocket(m_handle);
#else
	::close(m_handle);
#endif
	m_handle = -1;
 }

// Send the \c size bytes at \c data.
	size_t
BSDSocket::Data::write(ByteBuffer& data)
{
	auto pMessage = data.current();
	auto byteCount = static_cast<int>(data.remaining());
	LOGLOG_TRACE(m_log, "write:"
		<< " byteCount " << byteCount
		<< " to " << *m_remoteAddress
		<< "\n" << MessageData(pMessage, byteCount)
		);
	int rs = sendto
		( m_handle
		, pMessage
		, byteCount
		, 0
		, reinterpret_cast<struct sockaddr*>(m_remoteAddress.get())
		, (int)m_remoteAddressSize
		);
	if (rs < 0)
		throw UnexpectedSystemError("send");
	data.increment_position(byteCount);
	return byteCount;
}

// Set up \c m_remote for a \c m_inetType connection on \c port to \c address
	void
BSDSocket::Data::setRemote(const InetAddressPtr& address, int port)
{
	LOG4CXX_ENCODE_CHAR(hostAddress, address->getHostAddress());
	LOGLOG_DEBUG(m_log, "setRemote:"
		<< " hostAddress " << hostAddress
		<< " port " << port
		<< " inetType " << m_inetType
		<< " ipVersion " << m_inetFamily
		);
	struct addrinfo hints;
	memset(&hints, 0, sizeof (hints));
	hints.ai_family = m_inetFamily;
	hints.ai_socktype = m_inetType;
	auto service = std::to_string(port);
	int rs = getaddrinfo(hostAddress.c_str(), service.c_str(), &hints, &m_remote);
#ifdef WIN32
	if (0 != rs)
		throw UnexpectedSystemError(rs, "getaddrinfo");
#else
	if (0 == rs)
		;
	else if (EAI_SYSTEM == rs)
		throw UnexpectedSystemError("getaddrinfo");
	else
		throw UnexpectedSystemError(rs, gai_strerror(rs), "getaddrinfo");
#endif
	setRemoteAddress(m_remote->ai_addr, m_remote->ai_addrlen);
	setInternetPort(m_remote->ai_addr, port);
}

// Initialise \c m_remoteAddress from \c data
	void
BSDSocket::Data::setRemoteAddress(const struct sockaddr* data, size_t dataSize)
{
	LOGLOG_DEBUG(m_log, "setRemoteAddress:" << " size " << dataSize << " address " << *data);
	m_remoteAddressSize = SockSizeType(std::min(dataSize, sizeof (SockAddrType)));
	memcpy(m_remoteAddress.get(), data, m_remoteAddressSize);
}

// Initialise the port field of \c addr to \c port
	void
BSDSocket::Data::setInternetPort(struct sockaddr* addr, int port)
{
	LOGLOG_DEBUG(m_log, "setInternetPort: " << port);
	if (AF_INET == addr->sa_family)
	{
		struct sockaddr_in* ipv4Data = reinterpret_cast<struct sockaddr_in*>(addr);
		ipv4Data->sin_port = htons(port);
	}
	else
	{
		struct sockaddr_in6* ipv6Data = reinterpret_cast<struct sockaddr_in6*>(addr);
		ipv6Data->sin6_port = htons(port);
	}
}

IMPLEMENT_LOG4CXX_OBJECT(BSDSocket)

	const int
BSDSocket::DefaultPort{ 4560 };

#define _priv static_cast<Data*>(m_priv.get())

// A \c isDatagramType connection
BSDSocket::BSDSocket(bool isDatagramType, bool ipV6)
	: Socket{ std::make_unique<Data>(isDatagramType, ipV6) }
{
}

// A \c inetType connection on \c port to \c address (or as a server if 0)
BSDSocket::BSDSocket(const InetAddressPtr& address, int port, bool isDatagramType, bool ipV6)
	: Socket{ std::make_unique<Data>(address, port, isDatagramType, ipV6) }
{
}

BSDSocket::~BSDSocket()
{
}

	void
BSDSocket::setNonBlocking(bool newValue)
{
#ifdef WIN32
	u_long ulValue = newValue;
	if (ioctlsocket(_priv->m_handle, FIONBIO, &ulValue) == SOCKET_ERROR)
		throw UnexpectedSystemError(WSAGetLastError(), "ioctlsocket" );
#else
	int fd_flags = fcntl(_priv->m_handle, F_GETFL, 0);
#if defined(O_NONBLOCK)
	fd_flags |= O_NONBLOCK;
#elif defined(O_NDELAY)
	fd_flags |= O_NDELAY;
#elif defined(FNDELAY)
	fd_flags |= FNDELAY;
#else
#error Making sockets non-blocking not supported on your platform.
#endif
	if (fcntl(_priv->m_handle, F_SETFL, fd_flags) == -1)
		throw UnexpectedSystemError("fcntl");
#endif
}

// Prepare the channel for use.
	void
BSDSocket::open()
{
	_priv->open();
}

// Is the port available for use?
	bool
BSDSocket::is_open()
{
	return 0 <= _priv->m_handle;
}

// Release resources required by an open channel.
	void
BSDSocket::close()
{
	_priv->close();
}

// Send the \c size bytes at \c data.
	size_t
BSDSocket::write(ByteBuffer& data)
{
	return _priv->write(data);
}

} // namespace LOG4CXX_NS::helpers
