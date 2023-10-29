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

#ifndef _LOG4CXX_MDC_H
#define _LOG4CXX_MDC_H

#include <log4cxx/log4cxx.h>
#include <log4cxx/logstring.h>
#include <map>

namespace LOG4CXX_NS
{

/**
A <em>Mapped Diagnostic Context</em>, or
MDC in short, is an instrument for distinguishing interleaved log
output from different sources. Log output is typically interleaved
when a server handles multiple clients near-simultaneously.

#MDC provides a constructor and destructor which simply call the #put and
#remove methods, allowing for automatic cleanup when the current scope ends.

#MDC operations such as #put, #remove and #clear
affect only logging events emitted in the <em>calling</em> thread.
The contexts of other threads are not changed.
That is, <em><b>contexts are managed on a per thread basis</b></em>.

The MDC class is similar to the {@link log4cxx::NDC NDC} class except that it is
based on a map instead of a stack.
*/
class LOG4CXX_EXPORT MDC
{
	public:
		/** String to string stl map.
		*/
		typedef std::map<LogString, LogString> Map;

		/**
		 *  Places a key/value pair in the MDC for the current thread
		 *    which will be removed during the corresponding destructor.  Both
		 *    construction and destruction are expected to be on the same thread.
		 *    @param key context identifier
		 *    @param value a string that distinguishes this context.
		 */
		MDC(const std::string& key, const std::string& value);
		~MDC();

		/**
		* Set the <code>key</code> context in the current thread's context map to <code>value</code>.
		*
		* <p>If the current thread does not have a context map it is
		* created as a side effect.
		 *    @param key context identifier
		 *    @param value a string that distinguishes this context.
		*/
		static void put(const std::string& key, const std::string& value);
		/**
		* Set the <code>key</code> context in the current thread's context map to <code>value</code>.
		*
		* <p>If the current thread does not have a context map it is
		* created as a side effect.
		* */
		static void putLS(const LogString& key, const LogString& value);

		/**
		* Get the context identified by the <code>key</code> parameter.
		*
		*  <p>This method has no side effects.
		*  @param key context identifier.
		*  @return value for key, empty if not set.
		* */
		static std::string get(const std::string& key);
		/**
		 *  Gets the context identified by the <code>key</code> parameter.
		 *  @param key context key.
		 *  @param dest destination to which value is appended.
		 *  @return true if key has associated value.
		 */
		static bool get(const LogString& key, LogString& dest);

		/**
		* Remove the the context identified by the <code>key</code>
		* parameter.
		*  @param key context identifier.
		* @return value if key had been set, empty if not.
		*/
		static std::string remove(const std::string& key);
#if LOG4CXX_WCHAR_T_API
		/**
		 *  Places a key/value pair in the MDC for the current thread
		 *    which will be removed during the corresponding destructor.  Both
		 *    construction and destruction are expected to be on the same thread.
		 *    @param key context identifier
		 *    @param value a string that distinguishes this context.
		 */
		MDC(const std::wstring& key, const std::wstring& value);
		/**
		*  Set the <code>key</code> context in the current thread's context map to <code>value</code>.
		*
		* <p>If the current thread does not have a context map it is
		* created as a side effect.
		 *    @param key context identifier
		 *    @param value a string that distinguishes this context.
		*/
		static void put(const std::wstring& key, const std::wstring& value);
		/**
		* Get the context identified by the <code>key</code> parameter.
		*
		*  <p>This method has no side effects.
		*  @param key context identifier.
		*  @return value for key, empty if not set.
		* */
		static std::wstring get(const std::wstring& key);
		/**
		* Remove the the context identified by the <code>key</code>
		* parameter.
		*  @param key context identifier.
		* @return value if key had been set, empty if not.
		*/
		static std::wstring remove(const std::wstring& key);
#endif
#if LOG4CXX_UNICHAR_API
		/**
		 *  Places a key/value pair in the MDC for the current thread
		 *    which will be removed during the corresponding destructor.  Both
		 *    construction and destruction are expected to be on the same thread.
		 *    @param key context identifier
		 *    @param value a string that distinguishes this context.
		 */
		MDC(const std::basic_string<UniChar>& key, const std::basic_string<UniChar>& value);
		/**
		*  Set the <code>key</code> context in the current thread's context map to <code>value</code>.
		*
		* <p>If the current thread does not have a context map it is
		* created as a side effect.
		 *    @param key context identifier
		 *    @param value the value.
		*/
		static void put(const std::basic_string<UniChar>& key, const std::basic_string<UniChar>& value);
		/**
		* Get the context identified by the <code>key</code> parameter.
		*
		*  <p>This method has no side effects.
		*  @param key context identifier.
		*  @return value for key, empty if not set.
		* */
		static std::basic_string<UniChar> get(const std::basic_string<UniChar>& key);
		/**
		* Remove the the context identified by the <code>key</code>
		* parameter.
		*  @param key context identifier.
		* @return value if key had been set, empty if not.
		*/
		static std::basic_string<UniChar> remove(const std::basic_string<UniChar>& key);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		 *  Places a key/value pair in the MDC for the current thread
		 *    which will be removed during the corresponding destructor.  Both
		 *    construction and destruction are expected to be on the same thread.
		 *    @param key context identifier
		 *    @param value a string that distinguishes this context.
		 */
		MDC(const CFStringRef& key, const CFStringRef& value);
		/**
		*  Set the <code>key</code> context in the current thread's context map to <code>value</code>.
		*
		* <p>If the current thread does not have a context map it is
		* created as a side effect.
		 *    @param key context identifier
		 *    @param value a string that distinguishes this context.
		*/
		static void put(const CFStringRef& key, const CFStringRef& value);
		/**
		* Get the context identified by the <code>key</code> parameter.
		*
		*  <p>This method has no side effects.
		*  @param key context identifier.
		*  @return value for key, empty if not set.
		* */
		static CFStringRef get(const CFStringRef& key);
		/**
		* Remove the the context identified by the <code>key</code>
		* parameter.
		*  @param key context identifier.
		* @return value if key had been set, empty if not.
		*/
		static CFStringRef remove(const CFStringRef& key);
#endif
		/**
		* Remove the the context identified by the <code>key</code>
		* parameter.
		*  @param key context identifier.
		* @param prevValue buffer to which previous value is appended.
		* @return true if key existed in MDC.
		*/
		static bool remove(const LogString& key, LogString& prevValue);

		/**
		* Clear all entries in the MDC.
		* <p>A thread that adds to the diagnostic context by calling
		* #put should call this method before exiting
		* to prevent unbounded memory usage.
		*/
		static void clear();

	private:
		MDC(const MDC&);
		MDC& operator=(const MDC&);
		LOG4CXX_DECLARE_PRIVATE_MEMBER(LogString, key)
}; // class MDC;
}  // namespace log4cxx


#endif // _LOG4CXX_MDC_H
