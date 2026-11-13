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

#ifndef _LOG4CXX_APPENDER_H
#define _LOG4CXX_APPENDER_H

#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/helpers/object.h>
#include <vector>


namespace LOG4CXX_NS
{
// Forward declarations
namespace spi
{
class LoggingEvent;
typedef std::shared_ptr<LoggingEvent> LoggingEventPtr;

class Filter;
typedef std::shared_ptr<Filter> FilterPtr;

class ErrorHandler;
typedef std::shared_ptr<ErrorHandler> ErrorHandlerPtr;
}

class Layout;
typedef std::shared_ptr<Layout> LayoutPtr;


/**
Implement this interface for your own strategies for outputting log
statements.
*/
class LOG4CXX_EXPORT Appender
	: public spi::OptionHandler
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Appender)

		virtual ~Appender() {}

		/**
		 Add a filter to the end of the filter list.
		*/
		virtual void addFilter(const spi::FilterPtr& newFilter) = 0;

		/**
		 Returns the head Filter. The Filters are organized in a linked list
		 and so all Filters on this Appender are available through the result.

		 @return the head Filter or null, if no Filters are present
		 */
		virtual spi::FilterPtr getFilter() const = 0;

		/**
		 Clear the list of filters by removing all the filters in it.
		*/
		virtual void clearFilters() = 0;

		/**
		 Release any resources allocated within the appender such as file
		 handles, network connections, etc.
		*/
		virtual void close() = 0;

		/**
		 Add a formatted equivalent of \c event to the output.
		 A Logger uses this entry point (via AppenderAttachable::appendLoopOnAppenders)
		 when a logging request is enabled.
		*/
		virtual void doAppend(const spi::LoggingEventPtr& event) = 0;
		/**
		@deprecated Backward compatability support will be removed in a future version.
		*/
		[[deprecated("Use doAppend() without a Pool parameter instead")]]
		void doAppend(const spi::LoggingEventPtr& event, helpers::Pool& pool);

		/**
		 Get the name of this appender. The name uniquely identifies the
		 appender.
		*/
		virtual LogString getName() const = 0;


		/**
		 Set the Layout for this appender.
		*/
		virtual void setLayout(const LayoutPtr& layout) = 0;

		/**
		 Returns this appenders layout.
		*/
		virtual LayoutPtr getLayout() const = 0;


		/**
		 Set the name of this appender. The name is used by other
		 components to identify this appender.
		*/
		virtual void setName(const LogString& name) = 0;

		/**
		@deprecated This method will be removed in a future version.
		*/
		[[deprecated("This method is no longer used by Log4cxx configurators")]]
		virtual bool requiresLayout() const;
};

LOG4CXX_PTR_DEF(Appender);
LOG4CXX_LIST_DEF(AppenderList, AppenderPtr);

}

#endif //_LOG4CXX_APPENDER_H
