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

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ConsoleAppender)


ConsoleAppender::ConsoleAppender()
 : target(getSystemOut())
{
	os = &tcout;
}

ConsoleAppender::ConsoleAppender(const LayoutPtr& layout)
 : target(getSystemOut())
{
	this->layout = layout;
	os = &tcout;
}

ConsoleAppender::ConsoleAppender(const LayoutPtr& layout, const String& target)
 : target(getSystemOut())
{
	this->layout = layout;

	setTarget(target);
	activateOptions();
}

ConsoleAppender::~ConsoleAppender()
{
	finalize();
}

const String& ConsoleAppender::getSystemOut() {
  static const String name("System.out");
  return name;
}

const String& ConsoleAppender::getSystemErr() {
  static const String name("System.err");
  return name;
}


void ConsoleAppender::setTarget(const String& value)
{
	String v = StringHelper::trim(value);

	if (StringHelper::equalsIgnoreCase(getSystemOut(), v))
	{
		target = getSystemOut();
	}
	else if (StringHelper::equalsIgnoreCase(getSystemErr(), v))
	{
		target = getSystemErr();
	}
	else
	{
		targetWarn(value);
	}
}

const String& ConsoleAppender::getTarget() const
{
	return target;
}

void ConsoleAppender::targetWarn(const String& val)
{
	LogLog::warn(_T("[")+val+_T("] should be system.out or system.err."));
	LogLog::warn(_T("Using previously set target, System.out by default."));
}

void ConsoleAppender::activateOptions()
{
	if(StringHelper::equalsIgnoreCase(getSystemOut(), target))
	{
		os = &tcout;
	}
	else if (StringHelper::equalsIgnoreCase(getSystemErr(), target))
	{
		os = &tcerr;
	}
}

void ConsoleAppender::setOption(const String& option, const String& value)
{
	if (StringHelper::equalsIgnoreCase(_T("target"), option))
	{
		setTarget(value);
	}
	else
	{
		WriterAppender::setOption(option, value);
	}
}






