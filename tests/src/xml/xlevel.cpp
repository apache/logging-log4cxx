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

#include "xlevel.h"
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_LEVEL(XLevel)

const LevelPtr XLevel::TRACE(XLevel::getTrace());
const LevelPtr XLevel::LETHAL(XLevel::getLethal());


XLevel::XLevel(int level, const wchar_t* wName, const char* name, int syslogEquivalent)
: Level(level, wName, name, syslogEquivalent)
{
}

const LevelPtr& XLevel::getTrace() {
  static const LevelPtr trace(new XLevel(XLevel::TRACE_INT, L"TRACE", "trace", 7));
  return trace;
}

const LevelPtr& XLevel::getLethal() {
  static const LevelPtr lethal(new XLevel(XLevel::LETHAL_INT, L"LETHAL", "lethal", 0));
  return lethal;
}

const LevelPtr& XLevel::toLevel(const LogString& sArg)
{
	return toLevel(sArg, getTrace());
}

const LevelPtr& XLevel::toLevel(int val)
{
	return toLevel(val, getTrace());
}

const LevelPtr& XLevel::toLevel(int val, const LevelPtr& defaultLevel)
{
	switch(val)
	{
		case TRACE_INT: return getTrace();
		case LETHAL_INT: return getLethal();
		default: return defaultLevel;
	}
}

const LevelPtr& XLevel::toLevel(const LogString& sArg, const LevelPtr& defaultLevel)
{
   if (sArg.empty())
    {
       return defaultLevel;
    }

    if (StringHelper::equalsIgnoreCase(sArg,
          LOG4CXX_STR("TRACE"), LOG4CXX_STR("trace"))) {
      return getTrace();
    }

    if (StringHelper::equalsIgnoreCase(sArg,
           LOG4CXX_STR("LETHAL"), LOG4CXX_STR("lethal"))) {
      return getLethal();
    }

    return Level::toLevel(sArg, defaultLevel);
}
