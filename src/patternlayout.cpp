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

#include <log4cxx/patternlayout.h>
#include <log4cxx/helpers/patternparser.h>
#include <log4cxx/helpers/patternconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/pool.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(PatternLayout)


int PatternLayout::BUF_SIZE = 256;
int PatternLayout::MAX_CAPACITY = 1024;

PatternLayout::PatternLayout()
{
  Pool pool;
  activateOptions(pool);
}

/**
Constructs a PatternLayout using the supplied conversion pattern.
*/
PatternLayout::PatternLayout(const LogString& pattern) : pattern(pattern)
{
  Pool pool;
  activateOptions(pool);
}

void PatternLayout::setConversionPattern(const LogString& conversionPattern)
{
    pattern = conversionPattern;
    Pool pool;
    activateOptions(pool);
}

void PatternLayout::format(LogString& output,
      const spi::LoggingEventPtr& event,
      Pool& pool) const
{
        PatternConverterPtr c = head;

        while(c != 0)
        {
                c->format(output, event, pool);
                c = c->next;
        }
}

PatternConverterPtr PatternLayout::createPatternParser(const LogString& pattern)
{
        return PatternParser(pattern, timeZone).parse();
}

void PatternLayout::setOption(const LogString& option, const LogString& value)
{
        if (StringHelper::equalsIgnoreCase(option,
               LOG4CXX_STR("CONVERSIONPATTERN"),
               LOG4CXX_STR("conversionpattern")))
        {
                pattern = value;
        }
        else if (StringHelper::equalsIgnoreCase(option,
               LOG4CXX_STR("TIMEZONE"),
               LOG4CXX_STR("timezone")))
        {
                timeZone = value;
        }
}

void PatternLayout::activateOptions(Pool& p)
{
        if (pattern.empty())
        {
        static const LogString DEFAULT_CONVERSION_PATTERN(LOG4CXX_STR("%m%n"));
                pattern = DEFAULT_CONVERSION_PATTERN;
        }

        head = createPatternParser(pattern);
}






