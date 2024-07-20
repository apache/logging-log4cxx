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
		~ThreadSpecificData();

		/**
		 *  Gets current thread specific data.
		 *  @return thread specific data, may be null.
		 */
		static ThreadSpecificData* getCurrentData();
		/**
		 *  Release this ThreadSpecficData if empty.
		 */
		void recycle();

		static void put(const LogString& key, const LogString& val);
		static void push(const LogString& val);
		static void inherit(const LOG4CXX_NS::NDC::Stack& stack);

		NDC::Stack& getStack();
		MDC::Map& getMap();

		template <typename T>
		static std::basic_ostringstream<T>& getStringStream()
		{
			return getStream(T());
		}
		static LogString& getThreadIdString();
		static LogString& getThreadName();

	private:
		static ThreadSpecificData& getDataNoThreads();
#if !LOG4CXX_LOGCHAR_IS_UNICHAR && !LOG4CXX_LOGCHAR_IS_WCHAR
		static std::basic_ostringstream<logchar>& getStream(logchar&);
#endif
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
		static std::basic_ostringstream<wchar_t>& getStream(wchar_t&);
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
		static std::basic_ostringstream<UniChar>& getStream(UniChar&);
#endif
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(ThreadSpecificDataPrivate, m_priv)
};

}  // namespace helpers
} // namespace log4cxx


#endif
