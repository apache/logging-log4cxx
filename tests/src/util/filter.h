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

#ifndef _LOG4CXX_TESTS_UTIL_FILTER_H
#define _LOG4CXX_TESTS_UTIL_FILTER_H

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/exception.h>

#define BASIC_PAT LOG4CXX_STR("\\[0x[0-9A-F]*] (FATAL|ERROR|WARN|INFO|DEBUG)")
#define ISO8601_PAT LOG4CXX_STR("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3}")
#define ABSOLUTE_DATE_AND_TIME_PAT \
        LOG4CXX_STR("^\\d{1,2} .{2,6}\\.? 200\\d \\d{2}:\\d{2}:\\d{2},\\d{3}")
#define ABSOLUTE_TIME_PAT LOG4CXX_STR("^\\d{2}:\\d{2}:\\d{2},\\d{3}")
#define RELATIVE_TIME_PAT LOG4CXX_STR("^\\d{1,10}")

namespace log4cxx
{
        class UnexpectedFormatException : public helpers::Exception
        {
        public:
              UnexpectedFormatException(const LogString& msg);
              UnexpectedFormatException(const UnexpectedFormatException&);
              UnexpectedFormatException& operator=(const UnexpectedFormatException&);
        private:
              static std::string formatMessage(const LogString& msg);
        };

        class Filter
        {
        public:
            Filter() {}
            virtual ~Filter() {}
                virtual LogString filter(const LogString& in)
                        const throw(UnexpectedFormatException) = 0;

                static std::string merge(const std::string& pattern,
                const std::string& in, const std::string& fmt);
                static bool match(const std::string& pattern,
                    const std::string& in);
                static std::wstring merge(const std::wstring& pattern,
                    const std::wstring& in, const std::wstring& fmt);
                static bool match(const std::wstring& pattern,
                    const std::wstring& in);

        private:
            Filter(const Filter&);
            Filter& operator=(const Filter&);
        };
}

#endif //_LOG4CXX_TESTS_UTIL_FILTER_H
