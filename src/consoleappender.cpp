/***************************************************************************
                          consoleappender.cpp  -  class ConsoleAppender
                             -------------------
    begin                : mar avr 15 2003
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

#include <log4cxx/level.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ConsoleAppender)

tstring ConsoleAppender::SYSTEM_OUT = _T("System.out");
tstring ConsoleAppender::SYSTEM_ERR = _T("System.err");

ConsoleAppender::ConsoleAppender()
 : target(SYSTEM_OUT)
{
	os = &tcout;
}

ConsoleAppender::ConsoleAppender(LayoutPtr layout)
 : target(SYSTEM_OUT)
{
	this->layout = layout;
	os = &tcout;
}

ConsoleAppender::ConsoleAppender(LayoutPtr layout, const tstring& target)
 : target(SYSTEM_OUT)
{
	this->layout = layout;

	setTarget(target);
	activateOptions();
}

ConsoleAppender::~ConsoleAppender()
{
	finalize();
}

void ConsoleAppender::setTarget(const tstring& value)
{
	tstring v = StringHelper::trim(value);

	if (StringHelper::equalsIgnoreCase(SYSTEM_OUT, v))
	{
		target = SYSTEM_OUT;
	}
	else if (StringHelper::equalsIgnoreCase(SYSTEM_ERR, v))
	{
		target = SYSTEM_ERR;
	}
	else
	{
		targetWarn(value);
	}
}

const tstring& ConsoleAppender::getTarget()
{
	return target;
}

void ConsoleAppender::targetWarn(const tstring& val)
{
	LogLog::warn(_T("[")+val+_T("] should be system.out or system.err."));
	LogLog::warn(_T("Using previously set target, System.out by default."));
}

void ConsoleAppender::activateOptions()
{
	if(StringHelper::equalsIgnoreCase(SYSTEM_OUT, target))
	{
		os = &tcout;
	}
	else if (StringHelper::equalsIgnoreCase(SYSTEM_ERR, target))
	{
		os = &tcerr;
	}
}

void ConsoleAppender::setOption(const tstring& option, const tstring& value)
{
	if (StringHelper::equalsIgnoreCase(_T("target"), option))
	{
		setTarget(value);
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}






