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

#ifndef _LOG4CXX_HELPERS_WIDELIFE_H
#define _LOG4CXX_HELPERS_WIDELIFE_H

#include <log4cxx/log4cxx.h>
#if defined(__cpp_concepts) && __cpp_concepts >= 201500
#include <concepts>
#endif

namespace LOG4CXX_NS
{
namespace helpers
{
	

/**
The WideLife wrapper is destined to prolongate the runtime logger state lifetime from static duration to infinite
*/
template <class T>
class WideLife
{
public:
	WideLife()
	{		
		new(&storage) T();
	}
	template <class Arg0, class... Args>
#if defined(__cpp_concepts) && __cpp_concepts >= 201500
		requires (!std::same_as<WideLife, Arg0>)
#endif
	WideLife(Arg0&& arg0, Args&&... args)
	{		
		new(&storage) T(std::forward<Arg0>(arg0), std::forward<Args>(args)...);
	}
	
	~WideLife()
	{
#if LOG4CXX_EVENTS_AT_EXIT
		// keep the holded value alive
#else
		value().~T();
#endif
	}

	T& value()
	{
		return *reinterpret_cast<T*>(&storage);
	}
	
	const T& value() const
	{
		return *reinterpret_cast<const T*>(&storage);
	}
	
	operator T&()
	{
		return value();
	}
	
	operator const T&() const
	{
		return value();
	}

private:
	alignas(T) char storage[sizeof(T)];
	// Non-copyable
	WideLife(const WideLife& other) = delete;
	WideLife(const WideLife&& other) = delete;
	// Non-assignable
	WideLife& operator=(const WideLife& other) = delete;
	WideLife& operator=(const WideLife&& other) = delete;
}; // class WideLife
}  // namespace helpers
} // namespace log4cx

#endif //_LOG4CXX_HELPERS_WIDELIFE_H
