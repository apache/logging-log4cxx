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

#include <log4cxx/helpers/formattinginfo.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/pool.h>

using namespace log4cxx::helpers;

FormattingInfo::FormattingInfo()
   : minChar(-1), maxChar(0x7FFFFFFF), leftAlign(false)
{
}

void FormattingInfo::reset()
{
        minChar = -1;
        maxChar = 0x7FFFFFFF;
        leftAlign = false;
}

void FormattingInfo::dump()
{
        Pool pool;
        LogLog::debug(((LogString) LOG4CXX_STR("minChar="))
           + StringHelper::toString(minChar, pool)
           + LOG4CXX_STR(", maxChar=")
           + StringHelper::toString(maxChar, pool)
           + LOG4CXX_STR(", leftAlign=")
           + (leftAlign ? LOG4CXX_STR("true") : LOG4CXX_STR("false")));
}



