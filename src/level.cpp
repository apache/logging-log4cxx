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

#include <log4cxx/level.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT_WITH_CUSTOM_CLASS(Level, LevelClass)

const LevelPtr& Level::getOff() {
   static LevelPtr level(new Level(Level::OFF_INT, "OFF", 0));
   return level;
}

const LevelPtr& Level::getFatal() {
   static LevelPtr level(new Level(Level::FATAL_INT, "FATAL", 0));
   return level;
}

const LevelPtr& Level::getError() {
   static LevelPtr level(new Level(Level::ERROR_INT, "ERROR", 3));
   return level;
}

const LevelPtr& Level::getWarn() {
   static LevelPtr level(new Level(Level::WARN_INT, "WARN", 4));
   return level;
}

const LevelPtr& Level::getInfo() {
   static LevelPtr level(new Level(Level::INFO_INT, "INFO", 6));
   return level;
}

const LevelPtr& Level::getDebug() {
   static LevelPtr level(new Level(Level::DEBUG_INT, "DEBUG", 7));
   return level;
}

const LevelPtr& Level::getAll() {
   static LevelPtr level(new Level(Level::ALL_INT, "ALL", 7));
   return level;
}

const LevelPtr Level::OFF(Level::getOff());
const LevelPtr Level::FATAL(Level::getFatal());
const LevelPtr Level::ERROR(Level::getError());
const LevelPtr Level::WARN(Level::getWarn());
const LevelPtr Level::INFO(Level::getInfo());
const LevelPtr Level::DEBUG(Level::getDebug());
const LevelPtr Level::ALL(Level::getAll());

Level::Level(int level, const String& levelStr, int syslogEquivalent)
: level(level), levelStr(levelStr), syslogEquivalent(syslogEquivalent)
{
}


const LevelPtr& Level::toLevel(const String& sArg)
{
    return toLevel(sArg, Level::getDebug());
}

const LevelPtr& Level::toLevel(int val)
{
    return toLevel(val, Level::getDebug());
}

const LevelPtr& Level::toLevel(int val, const LevelPtr& defaultLevel)
{
    switch(val)
    {
    case ALL_INT: return getAll();
    case DEBUG_INT: return getDebug();
    case INFO_INT: return getInfo();
    case WARN_INT: return getWarn();
    case ERROR_INT: return getError();
    case FATAL_INT: return getFatal();
    case OFF_INT: return getOff();
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

    if(s == (_T("ALL"))) return getAll();
    if(s == (_T("DEBUG"))) return getDebug();
    if(s == (_T("INFO"))) return getInfo();
    if(s == (_T("WARN")))  return getWarn();
    if(s == (_T("ERROR"))) return getError();
    if(s == (_T("FATAL"))) return getFatal();
    if(s == (_T("OFF"))) return getOff();

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



