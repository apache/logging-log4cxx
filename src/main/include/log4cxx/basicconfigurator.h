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

#ifndef _LOG4CXX_BASIC_CONFIGURATOR_H
#define _LOG4CXX_BASIC_CONFIGURATOR_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/logger.h>
#include <log4cxx/logstring.h>
#include <log4cxx/spi/configurator.h>

namespace LOG4CXX_NS
{
class Appender;
typedef std::shared_ptr<Appender> AppenderPtr;

/**
Use BasicConfigurator (static) methods to configure Log4cxx
when not using a configuration file.

For <code>key=value</code> format configuration see PropertyConfigurator.
For XML format configuration see xml::DOMConfigurator.
*/
class LOG4CXX_EXPORT BasicConfigurator
{
	protected:
		BasicConfigurator() {}

	public:
		/**
		Add a ConsoleAppender to the root logger that formats output using \c layout.

		If \c layout is not provided,
		use a PatternLayout with <code>%%r [%%t] %%p %%c %%x - %%m%%n</code>
		as the conversion pattern.
		*/
		static void configure(const LayoutPtr& layout = LayoutPtr());

		/**
		Add <code>appender</code> to the root logger.
		@param appender The appender to add to the root logger.
		*/
		static void configure(const AppenderPtr& appender);

		/**
		Reset the default hierarchy to its defaut. It is equivalent to
		calling
		<code>Logger::getDefaultHierarchy()->resetConfiguration()</code>.
		See Hierarchy#resetConfiguration() for more details.  */
		static void resetConfiguration();
}; // class BasicConfigurator
}  // namespace log4cxx

#endif //_LOG4CXX_BASIC_CONFIGURATOR_H
