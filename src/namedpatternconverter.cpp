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

#include <log4cxx/helpers/namedpatternconverter.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(NamedPatternConverter)

NamedPatternConverter::NamedPatternConverter(const FormattingInfo& fi,
                                             const std::vector<LogString>& options) :
PatternConverter(fi), precision(0) {
    setOptions(options);
}

void NamedPatternConverter::setOptions(const std::vector<LogString>& options) {
    if (options.size() > 0) {
        precision = StringHelper::toInt(options[0]);
        if (precision < 0) {
            LogString msg(LOG4CXX_STR("Precision options ("));
            msg += options[0];
            msg += LOG4CXX_STR(") isn't a positive integer.");
            LogLog::error(msg);
            precision = 0;
        }
    }
}


void NamedPatternConverter::convert(LogString& sbuf,
                const log4cxx::spi::LoggingEventPtr& event,
                log4cxx::helpers::Pool&) const {
    LogString n(getFullyQualifiedName(event));
    if (precision <= 0) {
        sbuf.append(n);
    } else {
        LogString::size_type len = n.length();

        // We substract 1 from 'len' when assigning to 'end' to avoid out of
        // bounds exception in return r.substring(end+1, len). This can happen if
        // precision is 1 and the category name ends with a dot.
        LogString::size_type end = len -1 ;
        for(int i = precision; i > 0; i--)
        {
                end = n.rfind(LOG4CXX_STR('.'), end-1);
                if(end == LogString::npos)
                {
                        sbuf.append(n);
                        return;
                }
        }
        sbuf.append(n, end+1, len - (end+1));
    }
}

