/***************************************************************************
                          inetadress.h  -  description
                             -------------------
    begin                : ven mai 9 2003
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

#ifndef _LOG4CXX_HELPER_INETADDRESS_H
#define _LOG4CXX_HELPER_INETADDRESS_H

#include <log4cxx/helpers/tchar.h>
#include <vector>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		class UnknownHostException : public Exception
		{
		public:
			tstring getMessage() { return tstring(); }
		};

		class InetAddress
		{
		public:
			InetAddress();
			
			/** Returns the raw IP address of this InetAddress  object.
			*/
			int getAddress() const;

			/** Determines all the IP addresses of a host, given the host's name.
			*/
			static std::vector<InetAddress> getAllByName(const tstring& host);

			/** Determines the IP address of a host, given the host's name.
			*/
			static InetAddress getByName(const tstring& host);

			/** Returns the IP address string "%d.%d.%d.%d".
			*/
			tstring getHostAddress() const;

			/** Gets the host name for this IP address.
			*/
			tstring getHostName() const;

			/** Returns the local host.
			*/
			static InetAddress  getLocalHost();

			/** Utility routine to check if the InetAddress is an IP multicast address.
			*/
			bool isMulticastAddress() const;

			/** Converts this IP address to a String.
			*/
			tstring toString() const; 

			int address;
		}; // class InetAddress
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPER_INETADDRESS_H
