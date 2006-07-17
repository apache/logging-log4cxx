/*
 * Copyright 1999,2005 The Apache Software Foundation.
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
#include <log4cxx/pattern/linelocationpatternconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::pattern;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(LineLocationPatternConverter)

LineLocationPatternConverter::LineLocationPatternConverter() :
   LoggingEventPatternConverter(LOG4CXX_STR("Line"),
      LOG4CXX_STR("line")) {
}

PatternConverterPtr LineLocationPatternConverter::newInstance(
   const std::vector<LogString>& /* options */) {
   static PatternConverterPtr instance(new LineLocationPatternConverter());
   return instance;
}

void LineLocationPatternConverter::format(
  const LoggingEventPtr& event,
  LogString& toAppendTo,
  Pool& p) const {
   toAppendTo.append(StringHelper::toString(
       event->getLocationInformation().getLineNumber(),
       p));
}
