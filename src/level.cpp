/*
 * Copyright 2003-2005 The Apache Software Foundation.
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

#include <log4cxx/logstring.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/aprinitializer.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT_WITH_CUSTOM_CLASS(Level, LevelClass)

const LevelPtr& Level::getOff() {
   static LevelPtr level(new Level(Level::OFF_INT, LOG4CXX_STR("OFF"), 0));
   return level;
}

const LevelPtr& Level::getFatal() {
   static LevelPtr level(new Level(Level::FATAL_INT, LOG4CXX_STR("FATAL"), 0));
   return level;
}

const LevelPtr& Level::getError() {
   static LevelPtr level(new Level(Level::ERROR_INT, LOG4CXX_STR("ERROR"), 3));
   return level;
}

const LevelPtr& Level::getWarn() {
   static LevelPtr level(new Level(Level::WARN_INT, LOG4CXX_STR("WARN"), 4));
   return level;
}

const LevelPtr& Level::getInfo() {
   static LevelPtr level(new Level(Level::INFO_INT, LOG4CXX_STR("INFO"), 6));
   return level;
}

const LevelPtr& Level::getDebug() {
   static LevelPtr level(new Level(Level::DEBUG_INT, LOG4CXX_STR("DEBUG"), 7));
   return level;
}

const LevelPtr& Level::getAll() {
   static LevelPtr level(new Level(Level::ALL_INT, LOG4CXX_STR("ALL"), 7));
   return level;
}



Level::Level(int level,
    const logchar* name, int syslogEquivalent)
: level(level), name(name), syslogEquivalent(syslogEquivalent)
{
   APRInitializer::initialize();
}


const LevelPtr& Level::toLevel(const std::string& sArg)
{
    return toLevel(sArg, Level::getDebug());
}

#if LOG4CXX_HAS_WCHAR_T
const LevelPtr& Level::toLevel(const std::wstring& sArg)
{
    return toLevel(sArg, Level::getDebug());
}
#endif

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

const LevelPtr& Level::toLevel(const std::string& sArg, const LevelPtr& defaultLevel)
{
    const size_t len = sArg.length();

    if (len == 4) {
      if (StringHelper::equalsIgnoreCase(sArg, "INFO", "info")) {
        return getInfo();
      }
      if (StringHelper::equalsIgnoreCase(sArg, "WARN", "warn")) {
        return getWarn();
      }
    } else {
      if (len == 5) {
        if (StringHelper::equalsIgnoreCase(sArg, "DEBUG", "debug")) {
          return getDebug();
        }
        if (StringHelper::equalsIgnoreCase(sArg, "ERROR", "error")) {
          return getError();
        }
        if (StringHelper::equalsIgnoreCase(sArg, "FATAL", "fatal")) {
          return getFatal();
        }
      } else {
        if (len == 3) {
          if (StringHelper::equalsIgnoreCase(sArg, "OFF", "off")) {
            return getOff();
          }
          if (StringHelper::equalsIgnoreCase(sArg, "ALL", "all")) {
            return getAll();
          }
        }
      }
    }

    return defaultLevel;
}

#if LOG4CXX_HAS_WCHAR_T
const LevelPtr& Level::toLevel(const std::wstring& sArg, const LevelPtr& defaultLevel)
{
    const size_t len = sArg.length();

    if (len == 4) {
      if (StringHelper::equalsIgnoreCase(sArg, L"INFO", L"info")) {
        return getInfo();
      }
      if (StringHelper::equalsIgnoreCase(sArg, L"WARN", L"warn")) {
        return getWarn();
      }
    } else {
      if (len == 5) {
        if (StringHelper::equalsIgnoreCase(sArg, L"DEBUG", L"debug")) {
          return getDebug();
        }
        if (StringHelper::equalsIgnoreCase(sArg, L"ERROR", L"error")) {
          return getError();
        }
        if (StringHelper::equalsIgnoreCase(sArg, L"FATAL", L"fatal")) {
          return getFatal();
        }
      } else {
        if (len == 3) {
          if (StringHelper::equalsIgnoreCase(sArg, L"OFF", L"off")) {
            return getOff();
          }
          if (StringHelper::equalsIgnoreCase(sArg, L"ALL", L"all")) {
            return getAll();
          }
        }
      }
    }

    return defaultLevel;
}
#endif

bool Level::equals(const LevelPtr& level) const
{
        return (this->level == level->level);
}

bool Level::isGreaterOrEqual(const LevelPtr& level) const
{
    return this->level >= level->level;
}

void Level::toString(std::string& str) const {
    Transcoder::encode(name, str);
}

#if LOG4CXX_HAS_WCHAR_T
void Level::toString(std::wstring& str) const {
    Transcoder::encode(name, str);
}
#endif

//
//   may be declared by some platform headers
//
#undef ERROR
#undef DEBUG

const LevelPtr Level::OFF(Level::getOff());
const LevelPtr Level::FATAL(Level::getFatal());
const LevelPtr Level::ERROR(Level::getError());
const LevelPtr Level::WARN(Level::getWarn());
const LevelPtr Level::INFO(Level::getInfo());
const LevelPtr Level::DEBUG(Level::getDebug());
const LevelPtr Level::ALL(Level::getAll());


