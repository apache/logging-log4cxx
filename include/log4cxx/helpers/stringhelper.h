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

#ifndef _LOG4CXX_HELPERS_STRING_HELPER_H
#define _LOG4CXX_HELPERS_STRING_HELPER_H

#include <log4cxx/portability.h>
#include <log4cxx/logstring.h>
#include <stdarg.h>

class apr_pool_t;

namespace log4cxx
{
    namespace helpers
    {
		/**
		String manipulation routines
		*/
        class LOG4CXX_EXPORT StringHelper
        {
           public:
            static std::string trim(const std::string& s);
            static std::wstring trim(const std::wstring& s);
            static bool endsWith(const std::string& s, const std::string& suffix);
            static bool endsWith(const std::wstring& s, const std::wstring& suffix);
            static bool equalsIgnoreCase(const std::string& s1, const char* upper, const char* lower);
            static bool equalsIgnoreCase(const std::wstring& s1, const wchar_t* upper, const wchar_t* lower);

            static int toInt(const std::string& s);
            static int toInt(const std::wstring& s);
            static log4cxx_int64_t toInt64(const std::string& s);
            static log4cxx_int64_t toInt64(const std::wstring& s);

            static LogString toString(int s, apr_pool_t* pool);
            static LogString toString(int s);

            static std::string toLowerCase(const std::string& s);
            static std::wstring toLowerCase(const std::wstring& s);

            static bool getline(std::string& buf, std::string& line);
            static bool getline(std::wstring& buf, std::wstring& line);

        };
    }
}

#endif //_LOG4CXX_HELPERS_STRING_HELPER_H
