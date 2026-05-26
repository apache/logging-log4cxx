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

#ifndef _LOG4CXX_HELPERS_STRING_HELPER_H
#define _LOG4CXX_HELPERS_STRING_HELPER_H

#include <log4cxx/logstring.h>
#include <vector>


namespace LOG4CXX_NS
{
namespace helpers
{
#if LOG4CXX_ABI_VERSION <= 15
class Pool;
#endif
/**
String manipulation routines
*/
class LOG4CXX_EXPORT StringHelper
{
	public:
		/// A copy of \c s without any leading or trailing space characters
		static LogString trim(const LogString& s);
		/// Does \c s begin with the characters of \c prefix?
		static bool startsWith(const LogString& s, const LogString& prefix);
		/// Does \c s end with the characters of \c suffix?
		static bool endsWith(const LogString& s, const LogString& suffix);
		/// Is each character in \c s identical to the character at the corresponding position in either \c upper or \c lower?
		static bool equalsIgnoreCase(const LogString& s, const logchar* upper, const logchar* lower);
		/// Is each character in \c s identical to the character at the corresponding position in either \c upper or \c lower?
		static bool equalsIgnoreCase(const LogString& s, const LogString& upper, const LogString& lower);

		/// The numeric value at the start of \c s.
		/// See <a href=https://en.cppreference.com/cpp/string/basic_string/stol>std::stoi</a> for more details.
		static int toInt(const LogString& s);
		/// The numeric value at the start of \c s.
		/// See <a href=https://en.cppreference.com/cpp/string/basic_string/stol>std::stoll</a> for more details.
		static int64_t toInt64(const LogString& s);

#if LOG4CXX_ABI_VERSION <= 15
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		static void toString(int i, Pool& pool, LogString& dst);
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		static void toString(int64_t i, Pool& pool, LogString& dst);
		/// @deprecated This function is deprecated and will be removed in a future version.
		[[ deprecated( "Pool is no longer required" ) ]]
		static void toString(size_t i, Pool& pool, LogString& dst);
#endif
		/// Append a textual version of \c i to \c dst.
		static void toString(int i, LogString& dst);
		/// Append a textual version of \c i to \c dst.
		static void toString(int64_t i, LogString& dst);
		/// Append a textual version of \c i to \c dst.
		static void toString(size_t i, LogString& dst);
		/// Using \c val, append either "true" or "false" to \c dst.
		static void toString(bool val, LogString& dst);

		/// A copy of \c s with any character in [A-Z]
		/// replaced by the corresponding character in [a-z]
		static LogString toLowerCase(const LogString& s);

		/// A copy of \c pattern with any 3-character '{', [0-9], '}', substring
		/// replaced by the corresponding value from \c params
		static LogString format(const LogString& pattern, const std::vector<LogString>& params);
};
}
}

#endif //_LOG4CXX_HELPERS_STRING_HELPER_H
