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



#include <log4cxx/pattern/propertiespatternconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/location/locationinfo.h>

using namespace log4cxx;
using namespace log4cxx::pattern;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(PropertiesPatternConverter)

PropertiesPatternConverter::PropertiesPatternConverter(const LogString& name,
      const LogString& propertyName) :
   LoggingEventPatternConverter(name,LOG4CXX_STR("property")),
   option(propertyName) {
}

PatternConverterPtr PropertiesPatternConverter::newInstance(
   const std::vector<LogString>& options) {
   if (options.size() == 0) {
      static PatternConverterPtr def(new PropertiesPatternConverter(
         LOG4CXX_STR("Properties"), LOG4CXX_STR("")));
      return def;
   }
   LogString converterName(LOG4CXX_STR("Property{"));
   converterName.append(options[0]);
   converterName.append(LOG4CXX_STR("}"));
   PatternConverterPtr converter(new PropertiesPatternConverter(
        converterName, options[0]));
   return converter;
}

void PropertiesPatternConverter::format(
  const LoggingEventPtr& event,
  LogString& toAppendTo,
  Pool& p) const {
    if (option.length() == 0) {
      toAppendTo.append(1, LOG4CXX_STR('{'));

      std::set<LogString> keySet(event->getMDCKeySet());

      for(std::set<LogString>::const_iterator iter = keySet.begin();
          iter != keySet.end();
          iter++) {
          toAppendTo.append(1, LOG4CXX_STR('{'));
          toAppendTo.append(*iter);
          toAppendTo.append(1, LOG4CXX_STR(','));
          toAppendTo.append(event->getMDC(*iter));
          toAppendTo.append(1, LOG4CXX_STR('}'));
      }

      toAppendTo.append(1, LOG4CXX_STR('}'));

    } else {
      toAppendTo.append(event->getMDC(option));
    }
 }

