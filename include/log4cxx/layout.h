/***************************************************************************
                          layout.h  -  description
                             -------------------
    begin                : mer avr 16 2003
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

#ifndef _LOG4CXX_LAYOUT_H
#define _LOG4CXX_LAYOUT_H

#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/spi/optionhandler.h>

namespace log4cxx
{
    class Layout;
    typedef helpers::ObjectPtrT<Layout> LayoutPtr;

    namespace spi
    {
		class LoggingEvent;
        typedef helpers::ObjectPtrT<LoggingEvent> LoggingEventPtr;
    };

	/**
	Extend this abstract class to create your own log layout format.
	*/
	class LOG4CXX_EXPORT Layout :
		public virtual spi::OptionHandler,
		public virtual helpers::ObjectImpl
	{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Layout)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(Layout)
			LOG4CXX_CAST_ENTRY(spi::OptionHandler)
		END_LOG4CXX_CAST_MAP()

		virtual ~Layout() {}

		/**
		Implement this method to create your own layout format.
		*/
		virtual void format(ostream& output, const spi::LoggingEventPtr& event) = 0;

		/**
		Returns the content type output by this layout. The base class
		returns "text/plain".
		*/
		virtual String getContentType() const { return _T("text/plain"); }

		/**
		Append the header for the layout format. The base class does
		nothing.
		*/
		virtual void appendHeader(ostream& output) {}

		/**
		Append the footer for the layout format. The base class does
		nothing.
		*/
		virtual void appendFooter(ostream& output) {}

		/**
		If the layout handles the throwable object contained within
		{@link spi::LoggingEvent LoggingEvent}, then the layout should return
		<code>false</code>. Otherwise, if the layout ignores throwable
		object, then the layout should return <code>true</code>.

		<p>The SimpleLayout, TTCCLayout, 
		PatternLayout all return <code>true</code>. The {@link
		xml::XMLLayout XMLLayout} returns <code>false</code>.
		*/
		virtual bool ignoresThrowable() = 0;
	};
};

#endif // _LOG4CXX_LAYOUT_H
