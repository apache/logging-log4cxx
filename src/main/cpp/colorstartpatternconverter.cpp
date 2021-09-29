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
#if defined(_MSC_VER)
	#pragma warning ( disable: 4231 4251 4275 4786 )
#endif

#include <log4cxx/logstring.h>
#include <log4cxx/pattern/colorstartpatternconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::pattern;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ColorStartPatternConverter)

ColorStartPatternConverter::ColorStartPatternConverter() :
	LoggingEventPatternConverter(LOG4CXX_STR("Color Start"),
		LOG4CXX_STR("colorStart"))
{
}

PatternConverterPtr ColorStartPatternConverter::newInstance(
	const std::vector<LogString>& /* options */)
{
	static PatternConverterPtr instance(new ColorStartPatternConverter());
	return instance;
}

void ColorStartPatternConverter::format(
	const LoggingEventPtr& event,
	LogString& toAppendTo,
	Pool& p) const
{

  log4cxx::LevelPtr lvl = event->getLevel();
  switch (lvl->toInt()){
    case log4cxx::Level::FATAL_INT:
      toAppendTo.append(LOG4CXX_STR("\x1B[35m")); //magenta
      break;
    case log4cxx::Level::ERROR_INT:
      toAppendTo.append(LOG4CXX_STR("\x1B[91m")); //red
      break;
    case log4cxx::Level::WARN_INT:
      toAppendTo.append(LOG4CXX_STR("\x1B[33m")); //yellow
      break;
    case log4cxx::Level::INFO_INT:
      toAppendTo.append(LOG4CXX_STR("\x1B[32m")); //green
      break;
    case log4cxx::Level::DEBUG_INT:
      toAppendTo.append(LOG4CXX_STR("\x1B[36m")); //cyan
      break;
    case log4cxx::Level::TRACE_INT:
      toAppendTo.append(LOG4CXX_STR("\x1B[34m")); //blue
      break;
    default:
      break;
  }
}
