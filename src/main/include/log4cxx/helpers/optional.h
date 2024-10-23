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

#ifndef LOG4CXX_OPTIONAL_HDR_
#define LOG4CXX_OPTIONAL_HDR_

#ifdef __has_include                           // Check if __has_include is present
#  if __has_include(<optional>)                // Check for a standard version
#    include <optional>
#    if defined(__cpp_lib_optional)            // C++ >= 17
namespace LOG4CXX_NS { template< class T > using Optional = std::optional<T>; }
#define LOG4CXX_HAS_STD_OPTIONAL 1
#    endif
#  elif __has_include(<experimental/optional>) // Check for an experimental version
#    include <experimental/optional>
namespace LOG4CXX_NS { template< class T > using Optional = std::experimental::optional<T>; }
#define LOG4CXX_HAS_STD_OPTIONAL 1
#  elif __has_include(<boost/optional.hpp>)    // Try with an external library
#    include <boost/optional.hpp>
namespace LOG4CXX_NS { template< class T > using Optional = boost::optional<T>; }
#define LOG4CXX_HAS_STD_OPTIONAL 1
#  else                                        // Not found at all
#define LOG4CXX_HAS_STD_OPTIONAL 0
#  endif
#endif

#if !LOG4CXX_HAS_STD_OPTIONAL // Implement a minimal Optional?
namespace LOG4CXX_NS
{
	template< class T >
class Optional : private std::pair<bool, T>
{
	using BaseType = std::pair<bool, T>;
public:
	Optional() : BaseType(false, T()) {}
	Optional& operator=(const T& value)
	{
		this->first = true;
		this->second = value;
		return *this;
	}
	constexpr explicit operator bool() const noexcept { return this->first; }
	constexpr bool has_value() const noexcept { return this->first; }
	constexpr const T& value() const noexcept { return this->second; }
};
} // namespace LOG4CXX_NS
#endif

#endif // LOG4CXX_OPTIONAL_HDR_
