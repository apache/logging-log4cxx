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
class LOG4CXX_EXPORT Layout :
	public virtual spi::OptionHandler,
	public virtual helpers::Object
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
		virtual void format(LogString& output,
			const spi::LoggingEventPtr& event, LOG4CXX_NS::helpers::Pool& pool) const = 0;

		/**
		Returns the content type output by this layout. The base class
		returns "text/plain".
		*/
		virtual LogString getContentType() const;

		/**
		Append the header for the layout format. The base class does
		nothing.
		*/
		virtual void appendHeader(LogString& output, LOG4CXX_NS::helpers::Pool& p);

		/**
		Append the footer for the layout format. The base class does
		nothing.
		*/
		virtual void appendFooter(LogString& output, LOG4CXX_NS::helpers::Pool& p);

		/**
		If the layout handles the throwable object contained within
		{@link spi::LoggingEvent LoggingEvent}, then the layout should return
		<code>false</code>. Otherwise, if the layout ignores throwable
		object, then the layout should return <code>true</code>.

		<p>The SimpleLayout, FMTLayout and PatternLayout return <code>true</code>.
		The other layouts return <code>false</code>.
		*/
		virtual bool ignoresThrowable() const = 0;

	protected:
		/**
		 * The expected length of a formatted event excluding the message text
		 */
		size_t getFormattedEventCharacterCount() const;
};
LOG4CXX_PTR_DEF(Layout);
}

#endif // _LOG4CXX_LAYOUT_H
