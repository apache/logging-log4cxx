/***************************************************************************
                          htmllayout.h  -  class HTMLLayout
                             -------------------
    begin                : dim mai 18 2003
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

#ifndef _LOG4CXX_HTML_LAYOUT_H
#define _LOG4CXX_HTML_LAYOUT_H

#include <log4cxx/layout.h>

namespace log4cxx
{
	namespace spi
	{
		class LoggingEvent;
	};
	
	/**
	This layout outputs events in a HTML table.
	*/
	class HTMLLayout : public Layout
	{
	protected:
		static tstring TRACE_PREFIX;

	private:
		/**
		A string constant used in naming the option for setting the the
		location information flag.  Current value of this string
		constant is <b>LocationInfo</b>.
		*/
		static tstring LOCATION_INFO_OPTION;

		/**
		A string constant used in naming the option for setting the the
		HTML document title.  Current value of this string
		constant is <b>Title</b>.
		*/
		static tstring TITLE_OPTION;

		// Print no location info by default
		bool locationInfo; //= false

		tstring title;

	public:
		HTMLLayout();

		/**
		The <b>LocationInfo</b> option takes a boolean value. By
		default, it is set to false which means there will be no location
		information output by this layout. If the the option is set to
		true, then the file name and line number of the statement
		at the origin of the log statement will be output.

		<p>If you are embedding this layout within an {@link
		net::SMTPAppender SMTPAppender} then make sure to set the
		<b>LocationInfo</b> option of that appender as well.
		*/
		inline void setLocationInfo(bool flocationInfoag)
			{ this->locationInfo = locationInfo; }

		/**
		Returns the current value of the <b>LocationInfo</b> option.
		*/
		inline bool getLocationInfo() const
			{ return locationInfo; }

		/**
		The <b>Title</b> option takes a String value. This option sets the
		document title of the generated HTML document.
		<p>Defaults to 'Log4cxx Log Messages'.
		*/
		inline void setTitle(const tstring& title)
			{ this->title = title; }

		/**
		Returns the current value of the <b>Title</b> option.
		*/
		inline const tstring& getTitle() const
			{ return title; }

		/**
		Returns the content type output by this layout, i.e "text/html".
		*/
		tstring getContentType() const { return _T("text/html"); }

		/**
		No options to activate.
		*/
		void activateOptions() {}

		/**
		Set options
		*/
		virtual void setOption(const std::string& option, const std::string& value);

		virtual void format(tostream& output, const spi::LoggingEvent& event);

		/**
		Append appropriate HTML headers.
		*/
		virtual void appendHeader(tostream& output);

		/**
		Append the appropriate HTML footers.
		*/
		virtual void appendFooter(tostream& output);

		/**
		The HTML layout handles the throwable contained in logging
		events. Hence, this method return <code>false</code>.  */
		virtual bool ignoresThrowable()
			{ return false; }
			
	}; // class HtmlLayout
}; // namespace log4cxx

#endif // _LOG4CXX_HTML_LAYOUT_H
