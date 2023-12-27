/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
#include <log4cxx/helpers/class.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/object.h>
#include <map>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/log4cxx.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>


#include <log4cxx/asyncappender.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/db/odbcappender.h>
#if defined(WIN32) || defined(_WIN32)
	#if !defined(_WIN32_WCE)
		#include <log4cxx/nt/nteventlogappender.h>
	#endif
	#include <log4cxx/nt/outputdebugstringappender.h>
#endif
#include <log4cxx/net/smtpappender.h>
#include <log4cxx/helpers/datagramsocket.h>
#include <log4cxx/net/syslogappender.h>
#include <log4cxx/net/telnetappender.h>
#include <log4cxx/writerappender.h>
#include <log4cxx/net/xmlsocketappender.h>
#include <log4cxx/layout.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/jsonlayout.h>
#include <log4cxx/htmllayout.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/xml/xmllayout.h>

#include <log4cxx/filter/levelmatchfilter.h>
#include <log4cxx/filter/levelrangefilter.h>
#include <log4cxx/filter/stringmatchfilter.h>
#include <log4cxx/filter/locationinfofilter.h>
#include <log4cxx/rolling/filterbasedtriggeringpolicy.h>
#include <log4cxx/rolling/fixedwindowrollingpolicy.h>
#include <log4cxx/rolling/manualtriggeringpolicy.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/rolling/sizebasedtriggeringpolicy.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>

#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/varia/fallbackerrorhandler.h>


using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::net;
using namespace LOG4CXX_NS::filter;
using namespace LOG4CXX_NS::xml;
using namespace LOG4CXX_NS::rolling;

namespace LOG4CXX_NS
{
uint32_t libraryVersion()
{
	// This function defined in log4cxx.h
	return LOG4CXX_VERSION;
}
}

#if LOG4CXX_ABI_VERSION <= 15
LOG4CXX_EXPORT uint32_t libraryVersion()
{
	return  LOG4CXX_NS::libraryVersion();
}
#endif

Class::Class()
{
}

Class::~Class()
{
}

LogString Class::toString() const
{
	return getName();
}

Object* Class::newInstance() const
{
	throw InstantiationException(LOG4CXX_STR("Cannot create new instances of Class."));
#if LOG4CXX_RETURN_AFTER_THROW
	return 0;
#endif
}



Class::ClassMap& Class::getRegistry()
{
	static WideLife<ClassMap> registry;
	return registry;
}

const Class& Class::forName(const LogString& className)
{
	LogString lowerName(StringHelper::toLowerCase(className));
	//
	//  check registry using full class name
	//
	const Class* clazz = getRegistry()[lowerName];

	if (clazz == 0)
	{
		LogString::size_type pos = className.find_last_of(LOG4CXX_STR(".$"));

		if (pos != LogString::npos)
		{
			LogString terminalName(lowerName, pos + 1, LogString::npos);
			clazz = getRegistry()[terminalName];

			if (clazz == 0)
			{
				registerClasses();
				clazz = getRegistry()[lowerName];

				if (clazz == 0)
				{
					clazz = getRegistry()[terminalName];
				}
			}
		}
		else
		{
			registerClasses();
			clazz = getRegistry()[lowerName];
		}
	}

	if (clazz == 0)
	{
		throw ClassNotFoundException(className);
	}

	return *clazz;
}

bool Class::registerClass(const Class& newClass)
{
	getRegistry()[StringHelper::toLowerCase(newClass.getName())] = &newClass;
	return true;
}

void Class::registerClasses()
{
	AsyncAppender::registerClass();
	ConsoleAppender::registerClass();
	FileAppender::registerClass();
	LOG4CXX_NS::db::ODBCAppender::registerClass();
#if (defined(WIN32) || defined(_WIN32))
#if !defined(_WIN32_WCE)
	LOG4CXX_NS::nt::NTEventLogAppender::registerClass();
#endif
	LOG4CXX_NS::nt::OutputDebugStringAppender::registerClass();
#endif
	SMTPAppender::registerClass();
	JSONLayout::registerClass();
	HTMLLayout::registerClass();
	PatternLayout::registerClass();
	SimpleLayout::registerClass();
	XMLLayout::registerClass();
	LevelMatchFilter::registerClass();
	LevelRangeFilter::registerClass();
	StringMatchFilter::registerClass();
	LocationInfoFilter::registerClass();
	LOG4CXX_NS::rolling::RollingFileAppender::registerClass();
	LOG4CXX_NS::rolling::SizeBasedTriggeringPolicy::registerClass();
	LOG4CXX_NS::rolling::TimeBasedRollingPolicy::registerClass();
	LOG4CXX_NS::rolling::ManualTriggeringPolicy::registerClass();
	LOG4CXX_NS::rolling::FixedWindowRollingPolicy::registerClass();
	LOG4CXX_NS::rolling::FilterBasedTriggeringPolicy::registerClass();
#if LOG4CXX_HAS_DOMCONFIGURATOR
	LOG4CXX_NS::xml::DOMConfigurator::registerClass();
#endif
	LOG4CXX_NS::PropertyConfigurator::registerClass();
	LOG4CXX_NS::varia::FallbackErrorHandler::registerClass();
#if LOG4CXX_HAS_NETWORKING
	TelnetAppender::registerClass();
	XMLSocketAppender::registerClass();
	SyslogAppender::registerClass();
#endif
}

