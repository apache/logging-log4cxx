/***************************************************************************
                          socketnode.cpp  -  class SocketNode
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

#include <log4cxx/logger.h>
#include <log4cxx/net/socketnode.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/socketinputstream.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx;
using namespace log4cxx::net;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(SocketNode)

SocketNode::SocketNode(helpers::SocketPtr socket, spi::LoggerRepositoryPtr hierarchy)
 : hierarchy(hierarchy)
{
	is = socket->getInputStream();
}

void SocketNode::run()
{
	LoggingEventPtr event = new LoggingEvent();
	LoggerPtr remoteLogger;

	try
	{
		while(true)
		{
			// read an event from the wire
			event->read(is);
			
			// get a logger from the hierarchy.
			// The name of the logger is taken to be the 
			// name contained in the event.
			if (event->getLoggerName() == _T("root"))
			{
				remoteLogger = hierarchy->getRootLogger();
			}
			else
			{
				remoteLogger =
					hierarchy->getLogger(event->getLoggerName());
			}

			// apply the logger-level filter
			if(event->getLevel()->isGreaterOrEqual(
				remoteLogger->getEffectiveLevel()))
			{
				// finally log the event as if was generated locally
				remoteLogger->callAppenders(event);
			}
		}
	}
	catch(EOFException&)
	{
		LogLog::debug(_T("Caught EOFException. Closing connection."));
	}
	catch(SocketException&)
	{
		LogLog::debug(_T("Caught SocketException. Closing connection"));
	}
    catch(IOException& e)
    {
      LogLog::debug(_T("Caught IOException."), e);
      LogLog::debug(_T("Closing connection."));
    }
    catch(Exception& e)
    {
      LogLog::error(_T("Unexpected exception. Closing connection."), e);
    }

	try
	{
		is->close();
	}
	catch(SocketException& e)
	{
		LogLog::debug(_T("Could not close SocketNode connection: "), e);
	}
}
