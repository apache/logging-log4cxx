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

#ifndef _LOG4CXX_HELPERS_THREAD_SPECIFIC_DATA_H
#define _LOG4CXX_HELPERS_THREAD_SPECIFIC_DATA_H

#include <log4cxx/ndc.h>
#include <log4cxx/mdc.h>

namespace LOG4CXX_NS
{
namespace helpers
{
/**
  *   This class contains all the thread-specific
  *   data in use by log4cxx.
  */
class LOG4CXX_EXPORT ThreadSpecificData
{
	public:
		ThreadSpecificData();
		ThreadSpecificData(ThreadSpecificData&& other);
		~ThreadSpecificData();

		/**
		 *  Gets current thread specific data.
		 *  @return a pointer that is non-null prior to application exit.
		 */
		static ThreadSpecificData* getCurrentData();

		/**
		 *  Remove current thread data from APR if the diagnostic context is empty.
		 */
		void recycle();

		/**
		 *  Add the \c key \c val pair to the mapped diagnostic context of the current thread
		 */
		static void put(const LogString& key, const LogString& val);

		/**
		 *  Add \c val to the nested diagnostic context of the current thread
		 */
		static void push(const LogString& val);

		/**
		 *  Use \c stack as the nested diagnostic context of the current thread
		 */
		static void inherit(const NDC::Stack& stack);

		/**
		 *  The nested diagnostic context of the current thread
		 */
		NDC::Stack& getStack();

		/**
		 *  The mapped diagnostic context of the current thread
		 */
		MDC::Map& getMap();

		/**
		 *  A character outpur stream only assessable to the current thread
		 */
		template <typename T>
		static std::basic_ostringstream<T>& getStringStream()
		{
			return getStream(T());
		}

		/**
		 *  The names assigned to the current thread
		 */
		struct NamePair
		{
			LogString idString;
			LogString threadName;
		};
		using NamePairPtr = std::shared_ptr<NamePair>;
		/**
		 *  A reference counted pointer to the names of the current thread.
		 *
		 *  String references will remain valid
		 *  for the lifetime of this pointer (i.e. even after thread termination).
		 */
		static NamePairPtr getNames();
	private:
#if !LOG4CXX_LOGCHAR_IS_UNICHAR && !LOG4CXX_LOGCHAR_IS_WCHAR
		static std::basic_ostringstream<logchar>& getStream(const logchar&);
#endif
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
		static std::basic_ostringstream<wchar_t>& getStream(const wchar_t&);
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
		static std::basic_ostringstream<UniChar>& getStream(const UniChar&);
#endif
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(ThreadSpecificDataPrivate, m_priv)
};

}  // namespace helpers
} // namespace log4cxx


#endif
