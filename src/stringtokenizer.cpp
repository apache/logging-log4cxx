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

#include <log4cxx/helpers/stringtokenizer.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

StringTokenizer::StringTokenizer(const LogString& str, const LogString& delim)
: src(str), delim(delim), pos(0)
{
}

StringTokenizer::~StringTokenizer()
{
}

bool StringTokenizer::hasMoreTokens() const
{
        return (pos != LogString::npos
            && src.find_first_not_of(delim, pos) != LogString::npos);
}

LogString StringTokenizer::nextToken()
{
        if (pos != LogString::npos) {
            size_t nextPos = src.find_first_not_of(delim, pos);
            if (nextPos != LogString::npos) {
               pos = src.find_first_of(delim, nextPos);
               if (pos == LogString::npos) {
                 return src.substr(nextPos);
               }
               return src.substr(nextPos, pos - nextPos);
            }
        }
        throw NoSuchElementException();
		return LogString();
}
