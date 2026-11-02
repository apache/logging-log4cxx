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

#ifndef _LOG4CXX_SPI_ERROR_HANDLER_H
#define _LOG4CXX_SPI_ERROR_HANDLER_H

#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/spi/appenderattachable.h>
#include <log4cxx/spi/loggingevent.h>

namespace LOG4CXX_NS
{
namespace spi
{
enum ErrorCode
{ GENERIC_FAILURE = 0
, WRITE_FAILURE = 1
, FLUSH_FAILURE = 2
, CLOSE_FAILURE = 3
, OPEN_FAILURE = 4
, ROLLOVER_FAILURE = 7
, INVALID_CONFIGURATION = 8
};


/**
Appenders may delegate their error handling to
<code>ErrorHandlers</code>.

<p>Error handling is a particularly tedious to get right because by
definition errors are hard to predict and to reproduce.


<p>Please take the time to contact the author in case you discover
that errors are not properly handled. You are most welcome to
suggest new error handling policies or criticize existing policies.
*/
class LOG4CXX_EXPORT ErrorHandler
	: public OptionHandler
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(ErrorHandler)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(ErrorHandler)
		LOG4CXX_CAST_ENTRY(OptionHandler)
		END_LOG4CXX_CAST_MAP()

		virtual ~ErrorHandler() {}

		/**
		Override this to add \c clx to the list of collections to search for the failed appender.
		@param name the collection name.
		@param clx has a collection of appenders.
		*/
		virtual void addAppenderHolder(const LogString& name, const AppenderAttachablePtr& clx);

		/**
		Override this to add a reference to a logger to which the failing appender might be attached.
		The failing appender can be searched and replaced
		only in the loggers you add through this method.

		@param logger One of the loggers that will be searched.
		*/
		virtual void setLogger(const LoggerPtr& logger);

		/**
		This method is invoked when an exception is thown.

		@param context  Contextual information from where the exception is caught
		@param e        The execption that was caught.
		@param category The category of error.
		*/
		virtual void error
			( const LogString&       context
			, const std::exception&  e
			, ErrorCode              category = ErrorCode::GENERIC_FAILURE
			) = 0;

		/**
		This method is invoked when an error is detected
		but an exception is not available
		(e.g. Log4cxx is incorrectly configured).
		*/
		virtual void error(const LogString& message, ErrorCode category = ErrorCode::INVALID_CONFIGURATION) = 0;

		/**
		This method is invoked when an exception is thown while processing a spi::LoggingEvent.

		The default implementation discards \c event and calls the other error() overload.

		@param context  Contextual information from where the exception is caught
		@param e        The execption that was caught.
		@param category The category of error.
		@param event    The logging event that was not output
		*/
		virtual void error
			( const LogString&       context
			, const std::exception&  e
			, ErrorCode              category
			, const LoggingEventPtr& event
			);

		/**
		Override this to set the appender holding this error handler.
		This method is called by a xml::DOMConfigurator file processor
		when the error handler is associated with an appender.
		*/
		virtual void setAppender(const AppenderPtr& appender);

		/**
		Override this to set the appender to fallback upon in case of failure.
		This method is called by the xml::DOMConfigurator file processor
		when the error handler is associated with an appender.
		*/
		virtual void setBackupAppender(const AppenderPtr& appender);

		/**
		Override this to report whether an error been raised to this reporter.

		This implementation returns false always.
		*/
		virtual bool errorReported() const;

		using OptionHandler::activateOptions;
		/**
		\copybrief spi::OptionHandler::activateOptions()

		No action is performed in this implementation.
		*/
		void activateOptions(  ) override;
};

LOG4CXX_PTR_DEF(ErrorHandler);
}  //namespace spi
} //namespace log4cxx

#endif //_LOG4CXX_SPI_ERROR_HANDLER_H
