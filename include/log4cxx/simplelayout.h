/***************************************************************************
                          simplelayout.h  -  class SimpleLayout
                             -------------------
    begin                : dim avr 20 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_SIMPLE_LAYOUT_H
#define _LOG4CXX_SIMPLE_LAYOUT_H

#include <log4cxx/layout.h>

namespace log4cxx
{
	class SimpleLayout;
	typedef helpers::ObjectPtrT<SimpleLayout> SimpleLayoutPtr;

	/**
	SimpleLayout consists of the level of the log statement,
	followed by " - " and then the log message itself. For example,

	<pre>
		DEBUG - Hello world
	</pre>

	<p>

	<p>PatternLayout offers a much more powerful alternative.
	*/
	class LOG4CXX_EXPORT SimpleLayout : public Layout
	{
	public:
		DECLARE_LOG4CXX_OBJECT(SimpleLayout)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(SimpleLayout)
			LOG4CXX_CAST_ENTRY_CHAIN(Layout)
		END_LOG4CXX_CAST_MAP()

		/**
		Returns the log statement in a format consisting of the
		<code>level</code>, followed by " - " and then the
		<code>message</code>. For example, <pre> INFO - "A message"
		</pre>

		<p>The <code>category</code> parameter is ignored.
		<p>
		@return A byte array in SimpleLayout format.
		*/
		virtual void format(ostream& output, const spi::LoggingEventPtr& event);

		/**
		The SimpleLayout does not handle the throwable contained within
		{@link spi::LoggingEvent LoggingEvents}. Thus, it returns
		<code>true</code>.
		*/
		bool ignoresThrowable() { return true; }

		virtual void activateOptions() {}
		virtual void setOption(const String& option, const String& value) {}
	};
}; // namespace log4cxx

#endif //_LOG4CXX_SIMPLE_LAYOUT_H
