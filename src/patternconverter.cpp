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

#include <log4cxx/helpers/patternconverter.h>
#include <log4cxx/helpers/formattinginfo.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(PatternConverter)

PatternConverter::PatternConverter() : minChar(-1), maxChar(0x7FFFFFFF),
     leftAlign(false), next(), os()
{
}

PatternConverter::PatternConverter(const FormattingInfo& fi)
   : minChar(fi.minChar), maxChar(fi.maxChar), leftAlign(fi.leftAlign),
     next(), os()
{
}


/**
A template method for formatting in a converter specific way.
*/
void PatternConverter::format(LogString& sbuf,
     const spi::LoggingEventPtr& e,
     apr_pool_t* p) const
{
        if (minChar == -1 && maxChar == 0x7FFFFFFF)
        {
                convert(sbuf, e, p);
        }
        else
        {
                LogString s;
                convert(s, e, p);

                if (s.empty())
                {
                        if(0 < minChar)
                                sbuf.append(minChar, LOG4CXX_STR(' '));
                        return;
                }

                int len = s.size();

                if (len > maxChar)
                {
                        sbuf.append(s.substr(len-maxChar));
                }
                else if (len < minChar)
                {
                        if (leftAlign)
                        {
                                sbuf.append(s);
                                sbuf.append(minChar-len, LOG4CXX_STR(' '));
                        }
                        else
                        {
                                sbuf.append(minChar-len, LOG4CXX_STR(' '));
                                sbuf.append(s);
                        }
                }
                else
                        sbuf.append(s);
        }
}



