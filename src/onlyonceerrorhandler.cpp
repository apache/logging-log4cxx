/***************************************************************************
            onlyonceerrorhandler.cpp  -  class OnlyOnceErrorHandler
                             -------------------
    begin                : mer avr 16 2003
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

#include <log4cxx/appender.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/onlyonceerrorhandler.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

OnlyOnceErrorHandler::OnlyOnceErrorHandler() :
 WARN_PREFIX(_T("log4cxx warning: ")),
ERROR_PREFIX(_T("log4cxx error: ")), firstTime(true)
{
}


void OnlyOnceErrorHandler::setLogger(LoggerPtr logger)
{
}

void OnlyOnceErrorHandler::activateOptions()
{
}

void OnlyOnceErrorHandler::setOption(const tstring& name, const tstring& value)
{
}

void OnlyOnceErrorHandler::error(const tstring& message, log4cxx::helpers::Exception& e,
	int errorCode)
{
	if(firstTime)
	{
		LogLog::error(message, e);
		firstTime = false;
	}
}

void OnlyOnceErrorHandler::error(const tstring& message, log4cxx::helpers::Exception& e,
								 int errorCode, log4cxx::spi::LoggingEvent& event)
{
	error(message, e, errorCode);
}


void OnlyOnceErrorHandler::error(const tstring& message)
{
	if(firstTime)
	{
		LogLog::error(message);
		firstTime = false;
	}
}


void OnlyOnceErrorHandler::setAppender(AppenderPtr appender)
{
}


void OnlyOnceErrorHandler::setBackupAppender(AppenderPtr appender)
{
}
