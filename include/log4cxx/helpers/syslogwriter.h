/***************************************************************************
                          syslogwriter.h  -  class SyslogWriter
                             -------------------
    begin                : 2003/08/03
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

#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/inetaddress.h>

 namespace log4cxx
{
	namespace helpers
	{
		class DatagramSocket;
		typedef helpers::ObjectPtrT<DatagramSocket> DatagramSocketPtr;

		/**
		SyslogWriter is a wrapper around the DatagramSocket class
		it writes text to the specified host on the port 514 (UNIX syslog)
		*/
		class LOG4CXX_EXPORT SyslogWriter
		{
		public:
			SyslogWriter(const String& syslogHost);
			void write(const String& string);

		private:
			String syslogHost;
			InetAddress address;
			DatagramSocketPtr ds;
		};
	}; // namespace helpers
}; // namespace log4cxx
