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
    typedef helpers::ObjectPtr<Layout> LayoutPtr;

    namespace spi
    {
		class LoggingEvent;
    };

	/**
	Extend this abstract class to create your own log layout format.
	*/
	class Layout :
		public virtual spi::OptionHandler,
		public virtual helpers::ObjectImpl
	{
	public:
		virtual ~Layout() {}

		/**
		Implement this method to create your own layout format.
		*/
		virtual void format(tostream& output, const spi::LoggingEvent& event) = 0;

		/**
		Returns the content type output by this layout. The base class
		returns "text/plain".
		*/
		tstring getContentType() const { return _T("text/plain"); }

		/**
		Append the header for the layout format. The base class does
		nothing.
		*/
		virtual void appendHeader(tostream& output) {}

		/**
		Append the footer for the layout format. The base class does
		nothing.
		*/
		virtual void appendFooter(tostream& output) {}

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
