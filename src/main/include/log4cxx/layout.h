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

#ifndef _LOG4CXX_LAYOUT_H
#define _LOG4CXX_LAYOUT_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/spi/loggingevent.h>


namespace LOG4CXX_NS
{
/**
Extend this abstract class to create your own log layout format.
*/
class LOG4CXX_EXPORT Layout
#if LOG4CXX_ABI_VERSION <= 15
	: public virtual spi::OptionHandler
	, public virtual helpers::Object
#else
	: public spi::OptionHandler
#endif
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Layout)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Layout)
		LOG4CXX_CAST_ENTRY(spi::OptionHandler)
		END_LOG4CXX_CAST_MAP()

		virtual ~Layout();

		/**
		Implement this method to create your own layout format.
		*/
#if LOG4CXX_ABI_VERSION <= 15
		void format(LogString& output, const spi::LoggingEventPtr& event) const;
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to format() without a helpers::Pool parameter.
		*/
		virtual void format(LogString& output,
			const spi::LoggingEventPtr& event, LOG4CXX_NS::helpers::Pool& pool) const = 0;
#define LOG4CXX_FORMAT_LAYOUT_FORMAL_PARAMETERS LogString& output, const spi::LoggingEventPtr& event, helpers::Pool& p
#else
		virtual void format(LogString& output, const spi::LoggingEventPtr& event) const = 0;
#define LOG4CXX_FORMAT_LAYOUT_FORMAL_PARAMETERS LogString& output, const spi::LoggingEventPtr& event
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use format() without a Pool parameter instead")]]
		void format(LogString& output, const spi::LoggingEventPtr& event, helpers::Pool& p) const;
#endif

		/**
		Returns the content type output by this layout. The base class
		returns "text/plain".
		*/
		virtual LogString getContentType() const;

		/**
		Append the header for the layout format. The base class does
		nothing.
		*/
#if LOG4CXX_ABI_VERSION <= 15
		void appendHeader(LogString& output);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to appendHeader() without a helpers::Pool parameter.
		*/
		virtual void appendHeader(LogString& output, LOG4CXX_NS::helpers::Pool& p);
#define LOG4CXX_APPEND_HEADER_FORMAL_PARAMETERS LogString& output, LOG4CXX_NS::helpers::Pool& p
#else
		virtual void appendHeader(LogString& output);
#define LOG4CXX_APPEND_HEADER_FORMAL_PARAMETERS LogString& output
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use appendHeader() without a Pool parameter instead")]]
		void appendHeader(LogString& output, helpers::Pool& p);
#endif

		/**
		Append the footer for the layout format. The base class does
		nothing.
		*/
#if LOG4CXX_ABI_VERSION <= 15
		void appendFooter(LogString& output);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to appendFooter() without a helpers::Pool parameter.
		*/
		virtual void appendFooter(LogString& output, LOG4CXX_NS::helpers::Pool& p);
#define LOG4CXX_APPEND_FOOTER_FORMAL_PARAMETERS LogString& output, LOG4CXX_NS::helpers::Pool& p
#else
		virtual void appendFooter(LogString& output);
#define LOG4CXX_APPEND_FOOTER_FORMAL_PARAMETERS LogString& output
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use appendFooter() without a Pool parameter instead")]]
		void appendFooter(LogString& output, helpers::Pool& p);
#endif

		/**
		If the layout handles the throwable object contained within
		{@link spi::LoggingEvent LoggingEvent}, then the layout should return
		<code>false</code>. Otherwise, if the layout ignores throwable
		object, then the layout should return <code>true</code>.

		<p>The SimpleLayout, FMTLayout and PatternLayout return <code>true</code>.
		The other layouts return <code>false</code>.
		*/
		virtual bool ignoresThrowable() const = 0;

#if 15 < LOG4CXX_ABI_VERSION
		using spi::OptionHandler::activateOptions;
		/**
		\copybrief spi::OptionHandler::activateOptions()

		No action is performed in this implementation.
		*/
		void activateOptions( LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS ) override;
#endif
	protected:
		/**
		 * The expected length of a formatted event excluding the message text
		 */
		size_t getFormattedEventCharacterCount() const;
};
LOG4CXX_PTR_DEF(Layout);
}

#endif // _LOG4CXX_LAYOUT_H
