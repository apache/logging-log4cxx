/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define __STDC_CONSTANT_MACROS
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <algorithm>
#include <vector>
#include <iterator>
#include <algorithm>
#include <cctype>
#include <stdexcept>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

namespace
{
void checkFullyParsed(const std::string& value, std::size_t pos)
{
	while (pos < value.size() && std::isspace(static_cast<unsigned char>(value[pos])))
	{
		++pos;
	}

	if (pos != value.size())
	{
		throw std::invalid_argument("unexpected trailing characters");
	}
}
}

bool StringHelper::equalsIgnoreCase(const LogString& s1, const logchar* upper, const logchar* lower)
{
	for (const auto& item : s1)
	{
		if (0 == item || // OSS-Fuzz makes strings with embedded NUL characters
			(item != *upper && item != *lower))
		{
			return false;
		}
		++upper;
		++lower;
	}

	return 0 == *upper;
}

bool StringHelper::equalsIgnoreCase(const LogString& s1, const LogString& upper, const LogString& lower)
{
	LogString::const_iterator u = upper.begin();
	LogString::const_iterator l = lower.begin();
	LogString::const_iterator iter = s1.begin();

	for (;
		iter != s1.end() && u != upper.end() && l != lower.end();
		iter++, u++, l++)
	{
		if (*iter != *u && *iter != *l)
		{
			return false;
		}
	}

	return u == upper.end() && iter == s1.end();
}



LogString StringHelper::toLowerCase(const LogString& s)
{
	LogString d;
	std::transform(s.begin(), s.end(),
		std::insert_iterator<LogString>(d, d.begin()), tolower);
	return d;
}

LogString StringHelper::trim(const LogString& s)
{
	LogString::size_type pos = s.find_first_not_of(' ');

	if (pos == std::string::npos)
	{
		return LogString();
	}

	LogString::size_type n = s.find_last_not_of(' ') - pos + 1;
	return s.substr(pos, n);
}

bool StringHelper::startsWith(const LogString& s, const LogString& prefix)
{
	if (s.length() < prefix.length())
	{
		return false;
	}

	return s.compare(0, prefix.length(), prefix) == 0;
}

bool StringHelper::endsWith(const LogString& s, const LogString& suffix)
{
	if (suffix.length() <= s.length())
	{
		return s.compare(s.length() - suffix.length(), suffix.length(), suffix) == 0;
	}

	return false;
}


int StringHelper::toInt(const LogString& s)
{
	LOG4CXX_ENCODE_CHAR(as, s);
	std::size_t pos = 0;
	int value = std::stoi(as, &pos);
	checkFullyParsed(as, pos);
	return value;
}

int64_t StringHelper::toInt64(const LogString& s)
{
	LOG4CXX_ENCODE_CHAR(as, s);
	std::size_t pos = 0;
	auto value = std::stoll(as, &pos);
	checkFullyParsed(as, pos);
	return value;
}

void StringHelper::toString(int n, LogString& dst)
{
#if LOG4CXX_LOGCHAR_IS_WCHAR
	dst.append(std::to_wstring(n));
#else
	Transcoder::decode(std::to_string(n), dst);
#endif
}

void StringHelper::toString(bool val, LogString& dst)
{
	if (val)
	{
		dst.append(LOG4CXX_STR("true"));
	}
	else
	{
		dst.append(LOG4CXX_STR("false"));
	}
}


void StringHelper::toString(int64_t n, LogString& dst)
{
#if LOG4CXX_LOGCHAR_IS_WCHAR
	dst.append(std::to_wstring(n));
#else
	Transcoder::decode(std::to_string(n), dst);
#endif
}


void StringHelper::toString(size_t n, LogString& dst)
{
#if LOG4CXX_LOGCHAR_IS_WCHAR
	dst.append(std::to_wstring(n));
#else
	Transcoder::decode(std::to_string(n), dst);
#endif
}

LogString StringHelper::format(const LogString& pattern, const std::vector<LogString>& params)
{

	LogString result;
	LogString::size_type i = 0;

	while (i < pattern.length())
	{
		if (i + 2 < pattern.length() &&
			pattern[i] == 0x7B /* '{' */ && pattern[i + 1] >= 0x30 /* '0' */ &&
			pattern[i + 1] <= 0x39 /* '9' */ && pattern[i + 2] == 0x7D /* '}' */)
		{
			LogString::size_type arg = pattern[i + 1] - 0x30 /* '0' */;
			if (arg < params.size())
			{
				result = result + params[arg];
				i += 3;
				continue;
			}
		}
		result = result + pattern[i];
		i++;
	}

	return result;
}

#if LOG4CXX_ABI_VERSION <= 15
void StringHelper::toString(int n, Pool& pool, LogString& dst) { toString(n, dst); }
void StringHelper::toString(int64_t n, Pool& pool, LogString& dst) { toString(n, dst); }
void StringHelper::toString(size_t n, Pool& pool, LogString& dst) { toString(n, dst); }
#endif
