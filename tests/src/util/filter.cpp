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

#include <boost/regex.hpp>
#include "filter.h"
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace boost;

std::string Filter::merge(const std::string& pattern,
    const std::string& in, const std::string& fmt)
{
        boost::basic_regex<char> regex(pattern);
        return boost::regex_replace(in, regex, fmt);
}

bool Filter::match(const std::string& pattern,
      const std::string& in)
{
        boost::basic_regex<char> regex(pattern);
        return boost::regex_match(in, regex);
}

std::wstring Filter::merge(const std::wstring& pattern,
    const std::wstring& in, const std::wstring& fmt)
{
    boost::basic_regex<wchar_t> regex(pattern);
    return boost::regex_replace(in, regex, fmt);
}

bool Filter::match(const std::wstring& pattern,
      const std::wstring& in)
{
  boost::basic_regex<wchar_t> regex(pattern);
  return boost::regex_match(in, regex);
}


