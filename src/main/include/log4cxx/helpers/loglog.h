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

#ifndef _LOG4CXX_HELPERS_LOG_LOG_H
#define _LOG4CXX_HELPERS_LOG_LOG_H

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/widelife.h>
#include <exception>
#include <mutex>

namespace LOG4CXX_NS
{
namespace helpers
{
/**
This class used to output log statements from within the log4cxx package.

<p>Log4cxx components cannot make log4cxx logging calls. However, it is
sometimes useful for the user to learn about what log4cxx is
doing. You can enable log4cxx internal debug logging by calling the
<b>#setInternalDebugging</b> method.

<p>All LogLog messages are written to SystemErrWriter
prepended with the string "log4cxx: ".
*/
class LOG4CXX_EXPORT LogLog
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(LogLogPrivate, m_priv)

		friend WideLife<LogLog>;
		LogLog();
		LogLog(const LogLog&);
		LogLog& operator=(const LogLog&);
		static LogLog& getInstance();

	public:
		~LogLog();

		/**
		Use the value of \c enabled as the new internal debug logging state.
		*/
		static void setInternalDebugging(bool enabled);

		/**
		Output \c msg to SystemErrWriter if internal debug logging is enabled.
		*/
		static void debug(const LogString& msg);
		/**
		Output \c msg and <code>ex.what()</code> to SystemErrWriter if internal debug logging is enabled.
		*/
		static void debug(const LogString& msg, const std::exception& e);


		/**
		Output \c msg to SystemErrWriter unconditionally.
		*/
		static void error(const LogString& msg);
		/**
		Output \c msg and <code>ex.what()</code> to SystemErrWriter unconditionally.
		*/
		static void error(const LogString& msg, const std::exception& ex);


		/**
		Change quiet mode to \c newValue.

		In quiet mode LogLog generates strictly no output, not even
		for errors.

		@param newValue <code>true</code> for no output.
		*/
		static void setQuietMode(bool newValue);

		/**
		Output \c msg to SystemErrWriter unconditionally.
		*/
		static void warn(const LogString&  msg);
		/**
		Output \c msg and <code>ex.what()</code> to SystemErrWriter unconditionally.
		*/
		static void warn(const LogString&  msg, const std::exception& ex);

	private:
		static void emit(const LogString& msg);
		static void emit(const std::exception& ex);
};
}  // namespace helpers
} // namespace log4cxx

#define LOGLOG_DEBUG(log) { \
		LOG4CXX_NS::helpers::LogLog::debug(log) ; }

#define LOGLOG_WARN(log) { \
		LOG4CXX_NS::helpers::LogLog::warn(log) ; }

#define LOGLOG_ERROR(log) { \
		LOG4CXX_NS::helpers::LogLog::warn(log); }

#endif //_LOG4CXX_HELPERS_LOG_LOG_H
