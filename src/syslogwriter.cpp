/***************************************************************************
                          syslogwriter.cpp  -  class SyslogWriter
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

#include <log4cxx/helpers/syslogwriter.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/inetaddress.h>
#include <log4cxx/helpers/datagramsocket.h>
#include <log4cxx/helpers/datagrampacket.h>
#include <log4cxx/helpers/socketimpl.h>

#define SYSLOG_PORT 514

using namespace log4cxx::helpers;

SyslogWriter::SyslogWriter(const String& syslogHost)
: syslogHost(syslogHost)
{
	try
	{
		this->address = InetAddress::getByName(syslogHost);
	}
	catch(UnknownHostException& e)
	{
		LogLog::error(_T("Could not find ") + syslogHost +
			_T(". All logging will FAIL."), e);
	}

	try
	{
		this->ds = new DatagramSocket();
	}
	catch (SocketException& e)
	{
		LogLog::error(_T("Could not instantiate DatagramSocket to ") + syslogHost +
				_T(". All logging will FAIL."), e);
	}
}

void SyslogWriter::write(const String& string)
{
	USES_CONVERSION;
	const char * bytes = T2A(string.c_str());
	DatagramPacketPtr packet = new DatagramPacket((void *)bytes, string.length() + 1,
						address, SYSLOG_PORT);

	if(this->ds != 0)
	{
		ds->send(packet);
	}

}
