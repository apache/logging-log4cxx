/***************************************************************************
                                 xlevel.cpp
                             -------------------
    begin                : 2003/12/02
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include "xlevel.h"
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_LEVEL(XLevel)

#define TRACE_STR _T("TRACE")
#define LETHAL_STR _T("LETHAL")

const XLevelPtr XLevel::TRACE = new XLevel(XLevel::TRACE_INT, TRACE_STR, 7);
const XLevelPtr XLevel::LETHAL = new XLevel(XLevel::LETHAL_INT, LETHAL_STR, 0);

XLevel::XLevel(int level, const String& levelStr, int syslogEquivalent)
: Level(level, levelStr, syslogEquivalent)
{
}

const LevelPtr& XLevel::toLevel(const String& sArg)
{
	return toLevel(sArg, TRACE);
}

const LevelPtr& XLevel::toLevel(int val)
{
	return toLevel(val, TRACE);
}

const LevelPtr& XLevel::toLevel(int val, const LevelPtr& defaultLevel)
{
	switch(val)
	{
		case TRACE_INT: return (const LevelPtr&)TRACE;
		case LETHAL_INT: return (const LevelPtr&)LETHAL;
		default: return defaultLevel;
	}
}

const LevelPtr& XLevel::toLevel(const String& sArg, const LevelPtr& defaultLevel)
{
   if (sArg.empty())
    {
       return defaultLevel;
    }

    String s = StringHelper::toUpperCase(sArg);

    if(s == (TRACE_STR)) return (const LevelPtr&)TRACE;
    if(s == (LETHAL_STR)) return (const LevelPtr&)LETHAL;

    return defaultLevel;
}
