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
#include <log4cxx/consoleappender.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loglog.h>
#include <iostream>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ConsoleAppender)


ConsoleAppender::ConsoleAppender()
 : target(getSystemOut()), useErr(false)
{
}

ConsoleAppender::ConsoleAppender(const LayoutPtr& layout)
 : WriterAppender(layout), useErr(false),
   target(getSystemOut())
{
}

ConsoleAppender::ConsoleAppender(const LayoutPtr& layout, const LogString& target)
 : WriterAppender(layout), target(getSystemOut())
{
	setTarget(target);
	activateOptions(NULL);
}

ConsoleAppender::~ConsoleAppender()
{
	finalize();
}

const LogString& ConsoleAppender::getSystemOut() {
  static const LogString name(LOG4CXX_STR("System.out"));
  return name;
}

const LogString& ConsoleAppender::getSystemErr() {
  static const LogString name(LOG4CXX_STR("System.err"));
  return name;
}


void ConsoleAppender::setTarget(const LogString& value)
{
	LogString v = StringHelper::trim(value);

	if (StringHelper::equalsIgnoreCase(v,
              LOG4CXX_STR("SYSTEM.OUT"), LOG4CXX_STR("system.out")))
	{
		target = getSystemOut();
	}
	else if (StringHelper::equalsIgnoreCase(v,
               LOG4CXX_STR("SYSTEM.ERR"), LOG4CXX_STR("system.err")))
	{
		target = getSystemErr();
	}
	else
	{
		targetWarn(value);
	}
}

const LogString& ConsoleAppender::getTarget() const
{
	return target;
}

void ConsoleAppender::targetWarn(const LogString& val)
{
        LogLog::warn(((LogString) LOG4CXX_STR("["))
           + val +  LOG4CXX_STR("] should be system.out or system.err."));
	LogLog::warn(LOG4CXX_STR("Using previously set target, System.out by default."));
}

void ConsoleAppender::activateOptions(apr_pool_t* p)
{
	if(StringHelper::equalsIgnoreCase(target,
              LOG4CXX_STR("SYSTEM.OUT"), LOG4CXX_STR("system.out")))
	{
                useErr = false;
	}
	else if (StringHelper::equalsIgnoreCase(target,
              LOG4CXX_STR("SYSTEM.ERR"), LOG4CXX_STR("system.err")))
	{
                useErr = true;
	}
}

void ConsoleAppender::setOption(const LogString& option, const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option,
              LOG4CXX_STR("TARGET"), LOG4CXX_STR("target")))
	{
		setTarget(value);
	}
	else
	{
		WriterAppender::setOption(option, value);
	}
}


void ConsoleAppender::subAppend(const LogString& msg, apr_pool_t* p) {
        std::wstring wmsg;
        log4cxx::helpers::Transcoder::encode(msg, wmsg);
        if (useErr) {
          std::wcerr << wmsg << std::endl;
        } else {
          std::wcout << wmsg << std::endl;
        }
}






