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

#ifndef _LOG4CXX_CONSOLE_APPENDER_H
#define _LOG4CXX_CONSOLE_APPENDER_H

#include <log4cxx/writerappender.h>

namespace LOG4CXX_NS
{

/**
* ConsoleAppender appends log events to <code>stdout</code> or
* <code>stderr</code> using a layout specified by the user.
*
* The default target is <code>stdout</code>.
*
* You can use <a href="https://en.cppreference.com/w/c/io/fwide">fwide(stdout, 1)</a> in your configuration code
* or use the cmake directive `LOG4CXX_FORCE_WIDE_CONSOLE=ON` when building Log4cxx
* to force Log4cxx to use <a href="https://en.cppreference.com/w/c/io/fputws">fputws</a>.
* If doing this ensure the cmake directive `LOG4CXX_WCHAR_T` is also enabled.
*/
class LOG4CXX_EXPORT ConsoleAppender : public WriterAppender
{
	private:
		struct ConsoleAppenderPriv;

	public:
		DECLARE_LOG4CXX_OBJECT(ConsoleAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(ConsoleAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		/**
		* A <code>stdout</code> log event appender.
		*
		* See also #setLayout and #setTarget.
		*/
		ConsoleAppender();

		/**
		* A <code>stdout</code> log event appender formatted using \c layout.
		*
		* @param layout formats a log event
		*/
		ConsoleAppender(const LayoutPtr& layout);

		/**
		* A \c target log event appender formatted using \c layout.
		*
		* @param layout formats a log event
		* @param target the value provided by #getSystemOut or #getSystemErr
		*/
		ConsoleAppender(const LayoutPtr& layout, const LogString& target);
		~ConsoleAppender();


		/**
		*  Use \c newValue for the <b>target</b> property.
		*
		* @param newValue the value provided by #getSystemOut or #getSystemErr
		* */
		void setTarget(const LogString& newValue);

		/**
		* @returns the current value of the <b>target</b> property.
		*/
		LogString getTarget() const;

		/**
		\copybrief WriterAppender::activateOptions()

		No action is performed in this implementation.
		*/
		void activateOptions(helpers::Pool& p) override;
		/**
		\copybrief WriterAppender::setOption()

		Supported options | Supported values | Default value
		-------------- | ---------------- | ---------------
		Target | System.err,System.out | System.out

		\sa WriterAppender::setOption()
		 */
		void setOption(const LogString& option, const LogString& value) override;

		/**
		*  @returns the name recognised as <code>stdout</code>.
		*/
		static const LogString& getSystemOut();

		/**
		*  @returns the name recognised as <code>stderr</code>.
		*/
		static const LogString& getSystemErr();


	private:
		void targetWarn(const LogString& val);

};
LOG4CXX_PTR_DEF(ConsoleAppender);
}  //namespace log4cxx

#endif //_LOG4CXX_CONSOLE_APPENDER_H

