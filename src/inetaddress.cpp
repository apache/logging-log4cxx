/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined(WIN32) || defined(_WIN32)
#include <windows.h>
#include <winsock.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#endif

#include <log4cxx/helpers/inetaddress.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

InetAddress::InetAddress() : address(0)
{
}

/** Returns the raw IP address of this InetAddress  object.
*/
int InetAddress::getAddress() const
{
	return address;
}

/** Determines all the IP addresses of a host, given the host's name.
*/
std::vector<InetAddress> InetAddress::getAllByName(const LogString& host)
{
	struct hostent * hostinfo;

        std::string hostname;
        Transcoder::encode(host, hostname);
	hostinfo = ::gethostbyname(hostname.c_str());

	if (hostinfo == 0)
	{
                LogLog::error(
                   ((LogString) LOG4CXX_STR("Cannot get information about host :"))
                    + host);
		return std::vector<InetAddress>();
	}
	else
	{
		std::vector<InetAddress> addresses;
		InetAddress address;
		char ** addrs = hostinfo->h_addr_list;

		while(*addrs != 0)
		{
			address.address = ntohl(((in_addr *)*addrs)->s_addr);
			addresses.push_back(address);
		}

		return addresses;
	}

}

/** Determines the IP address of a host, given the host's name.
*/
InetAddress InetAddress::getByName(const LogString& host)
{
	struct hostent * hostinfo;
	InetAddress address;

        std::string hostname;
        Transcoder::encode(host, hostname);
	hostinfo = ::gethostbyname(hostname.c_str());

	if (hostinfo == 0)
	{
                LogLog::error(
                   ((LogString) LOG4CXX_STR("Cannot get information about host: "))
                    + host);
		throw UnknownHostException();
	}
	else
	{
		address.address = ntohl(((in_addr *)*hostinfo->h_addr_list)->s_addr);
	}

	return address;
}

/** Returns the IP address string "%d.%d.%d.%d".
*/
LogString InetAddress::getHostAddress() const
{
	in_addr addr;
	addr.s_addr = htonl(address);
	const char* rv = ::inet_ntoa(addr);
        LOG4CXX_DECODE_CHAR(wrv, rv);
        return wrv;
}

/** Gets the host name for this IP address.
*/
LogString InetAddress::getHostName() const
{
	LogString hostName;
	struct hostent * hostinfo;

	in_addr addr;
	addr.s_addr = htonl(address);
	hostinfo = ::gethostbyaddr((const char *)&addr, sizeof(addr), AF_INET);

	if (hostinfo != 0)
	{
                Transcoder::decode(hostinfo->h_name, strlen(hostinfo->h_name), hostName);
	}
	else
	{
                LogString msg(LOG4CXX_STR("Cannot get host name: "));
//  TODO:
//                msg += address->toString();
		LogLog::error(msg);
	}

	return hostName;
}

/** Returns the local host.
*/
InetAddress InetAddress::getLocalHost()
{
	InetAddress address;
	address.address = ntohl(inet_addr("127.0.0.1"));
	return address;
}

/** Utility routine to check if the InetAddress is an IP multicast address.
IP multicast address is a Class D address
i.e first four bits of the address are 1110.
*/
bool InetAddress::isMulticastAddress() const
{
	return (address & 0xF000) == 0xE000;
}

/** Converts this IP address to a String.
*/
LogString InetAddress::toString() const
{
        LogString rv(getHostName());
        rv.append(LOG4CXX_STR("/"));
        rv.append(getHostAddress());
        return rv;
}
