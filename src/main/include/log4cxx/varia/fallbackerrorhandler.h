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

#ifndef _LOG4CXX_VARIA_FALLBACK_ERROR_HANDLER_H
#define _LOG4CXX_VARIA_FALLBACK_ERROR_HANDLER_H

#include <log4cxx/spi/errorhandler.h>
#if LOG4CXX_ABI_VERSION <= 15
#include <log4cxx/logger.h>
#endif

namespace LOG4CXX_NS
{
namespace varia
{
/**
The <code>FallbackErrorHandler</code> implements the ErrorHandler
interface such that a secondary appender may be specified.  This
secondary appender takes over if the primary appender fails for
whatever reason.

<p>The error message is printed on <code>System.err</code>, and
logged in the new secondary appender.

Here is a sample configuration file that installs this error handler:
\anchor fallback-ref-example
\include async-fall-back-example.xml
*/
class LOG4CXX_EXPORT FallbackErrorHandler :
	public virtual spi::ErrorHandler
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(FallbackErrorHandlerPrivate, m_priv)

	public:
		DECLARE_LOG4CXX_OBJECT(FallbackErrorHandler)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(FallbackErrorHandler)
		LOG4CXX_CAST_ENTRY_CHAIN(spi::ErrorHandler)
		END_LOG4CXX_CAST_MAP()

		FallbackErrorHandler();
		~FallbackErrorHandler();

		/**
		Add \c clx to the list of collections to search for the failed appender.
		@param name used in log messages.
		@param clx has a collection of appenders.
		*/
		void addAppenderHolder(const LogString& name, const spi::AppenderAttachablePtr& clx) LOG4CXX_16_VIRTUAL_SPECIFIER;

		/**
		<em>Adds</em> the logger passed as parameter to the list of
		loggers that we need to search for in case of appender failure.
		*/
		void setLogger(const LoggerPtr& logger) override;

#if LOG4CXX_ABI_VERSION <= 15
		/**
		\copybrief spi::OptionHandler::activateOptions()

		No action is performed in this implementation.
		*/
		void activateOptions( LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS ) override;
#endif

		/**
		\copybrief spi::OptionHandler::setOption()
		 */
		void setOption(const LogString& option, const LogString& value) override;
		/**
		Prints the message and the stack trace of the exception on
		<code>System.err</code>.
		*/
		void error(const LogString& message, const std::exception& e,
			int errorCode) const override;

		/**
		Prints the message and the stack trace of the exception on
		<code>System.err</code>.
		*/
		void error(const LogString& message, const std::exception& e,
			int errorCode, const spi::LoggingEventPtr& event) const override;


		/**
		Print a the error message passed as parameter on
		<code>System.err</code>.
		*/
		void error(const LogString& message) const override;

		/**
		The appender to which this error handler is attached.
		*/
		void setAppender(const AppenderPtr& primary) override;

		/**
		Set the backup appender.
		*/
		void setBackupAppender(const AppenderPtr& backup) override;

		/**
		Has an error been reported?
		*/
#if 15 < LOG4CXX_ABI_VERSION
		bool errorReported() const override;
#else
		bool errorReported() const;
#endif
};
LOG4CXX_PTR_DEF(FallbackErrorHandler);

}  // namespace varia
} // namespace log4cxx

#endif //_LOG4CXX_VARIA_FALLBACK_ERROR_HANDLER_H

