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

#ifndef _LOG4CXX_SPI_OPTION_HANDLER_H
#define _LOG4CXX_SPI_OPTION_HANDLER_H

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/object.h>

namespace LOG4CXX_NS
{
namespace spi
{
class OptionHandler;
typedef std::shared_ptr<OptionHandler> OptionHandlerPtr;

/**
A string based interface to configure package components.
*/
class LOG4CXX_EXPORT OptionHandler : public virtual helpers::Object
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(OptionHandler)
		virtual ~OptionHandler() {}

		/**
		Activate the options that were previously set with calls to option
		setters.

		<p>This allows to defer activiation of the options until all
		options have been set. This is required for components which have
		related options that remain ambiguous until all are set.

		<p>For example, the FileAppender has
		the <code>File</code> and <b>Append</b> options both of
		which are ambiguous until the other is also set.
		*/
#if LOG4CXX_ABI_VERSION <= 15
#define LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS helpers::Pool& p
#define LOG4CXX_ACTIVATE_OPTIONS_PARAMETER p
		void activateOptions();
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to activateOptions() without parameters.
		*/
		virtual void activateOptions(helpers::Pool&) = 0;
#else
#define LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS
#define LOG4CXX_ACTIVATE_OPTIONS_PARAMETER
		virtual void activateOptions() = 0;
		/**
		@deprecated This function is deprecated and will be removed in a future version.
		Call activateOptions() without parameters instead.
		*/
		[[deprecated("Use activateOptions() without parameters instead")]]
		void activateOptions(helpers::Pool&);
#endif

		/**
		Set <code>option</code> to <code>value</code>.

		<p>The handling of each option depends on the OptionHandler
		instance. Some options may become active immediately whereas
		other may be activated only when #activateOptions is
		called.
		*/
		virtual void setOption(const LogString& option,
			const LogString& value) = 0;

}; // class OptionConverter
}  // namespace spi
} // namespace log4cxx


#if 15 < LOG4CXX_ABI_VERSION
#define LOG4CXX_16_VIRTUAL_SPECIFIER override
#else
#define LOG4CXX_16_VIRTUAL_SPECIFIER
#endif

#endif //_LOG4CXX_SPI_OPTION_HANDLER_H
