/***************************************************************************
                          level.cpp  -  description
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
#include <log4cxx/helpers/stringhelper.h>
 
using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT_WITH_CUSTOM_CLASS(Level, LevelClass)

const LevelPtr Level::OFF(new Level(Level::OFF_INT, _T("OFF"), 0));
const LevelPtr Level::FATAL(new Level(Level::FATAL_INT, _T("FATAL"), 0));
const LevelPtr Level::ERROR(new Level(Level::ERROR_INT, _T("ERROR"), 3));
const LevelPtr Level::WARN(new Level(Level::WARN_INT, _T("WARN"),  4));
const LevelPtr Level::INFO(new Level(Level::INFO_INT, _T("INFO"),  6));
const LevelPtr Level::DEBUG(new Level(Level::DEBUG_INT, _T("DEBUG"), 7));
const LevelPtr Level::ALL(new Level(Level::ALL_INT, _T("ALL"), 7));

Level::Level(int level, const String& levelStr, int syslogEquivalent)
: level(level), levelStr(levelStr), syslogEquivalent(syslogEquivalent)
{
}


const LevelPtr& Level::toLevel(const String& sArg)
{
    return toLevel(sArg, Level::DEBUG);
}

const LevelPtr& Level::toLevel(int val)
{
    return toLevel(val, Level::DEBUG);
}

const LevelPtr& Level::toLevel(int val, const LevelPtr& defaultLevel)
{
    switch(val)
    {
    case ALL_INT: return ALL;
    case DEBUG_INT: return DEBUG;
    case INFO_INT: return INFO;
    case WARN_INT: return WARN;
    case ERROR_INT: return ERROR;
    case FATAL_INT: return FATAL;
    case OFF_INT: return OFF;
    default: return defaultLevel;
    }
}

const LevelPtr& Level::toLevel(const String& sArg, const LevelPtr& defaultLevel)
{
    if (sArg.empty())
    {
       return defaultLevel;
    }

    String s = StringHelper::toUpperCase(sArg);

    if(s == (_T("ALL"))) return ALL;
    if(s == (_T("DEBUG"))) return DEBUG;
    if(s == (_T("INFO"))) return INFO;
    if(s == (_T("WARN")))  return WARN;
    if(s == (_T("ERROR"))) return ERROR;
    if(s == (_T("FATAL"))) return FATAL;
    if(s == (_T("OFF"))) return OFF;
    
    return defaultLevel;
}

bool Level::equals(const LevelPtr& level) const
{
	return (this->level == level->level);
}

int Level::getSyslogEquivalent() const
{
	return syslogEquivalent;
}

bool Level::isGreaterOrEqual(const LevelPtr& level) const
{
    return this->level >= level->level;
}

const String& Level::toString() const
{
	return levelStr;
}

int Level::toInt() const
{
	return level;
}



