/***************************************************************************
                          loglog.cpp  -  class LogLog
                             -------------------
    begin                : mar avr 15 2003
    copyright            : (C) 2003 by michael
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/helpers/loglog.h>

using namespace log4cxx::helpers;

bool LogLog::debugEnabled = false;  
bool LogLog::quietMode = false;

void LogLog::setInternalDebugging(bool debugEnabled)
{
	LogLog::debugEnabled = debugEnabled;
}

void LogLog::debug(const tstring& msg)
{
	if(debugEnabled && !quietMode)
	{
		tcout << msg << std::endl;
	}
}

void LogLog::debug(const tstring& msg, Exception& e)
{
	debug(msg);
	std::cerr << e.getMessage() << std::endl;
}


void LogLog::error(const tstring& msg)
{
	if(quietMode)
		return;

	tcerr << msg << std::endl;
}  

void LogLog::error(const tstring& msg, Exception& e)
{
	error(msg);
	std::cerr << e.getMessage() << std::endl;
}

void LogLog::setQuietMode(bool quietMode) 
{
	LogLog::quietMode = quietMode;
}

void LogLog::warn(const tstring& msg) 
{
	if(quietMode)
		return;
	
	tcerr << msg << std::endl;
}

void LogLog::warn(const tstring& msg, Exception& e)
{
	warn(msg);
	std::cerr << e.getMessage() << std::endl;
}
 
