/***************************************************************************
                          datelayout.h  -  description
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

#ifndef _LOG4CXX_HELPERS_DATE_LAYOUT_H
#define _LOG4CXX_HELPERS_DATE_LAYOUT_H

#include <log4cxx/layout.h>

namespace log4cxx
{
	namespace helpers
	{
		class DateFormat;
		
		/**
		This abstract layout takes care of all the date related options and
		formatting work.
		*/
 		class DateLayout : public Layout
		{
		public:
			/**
			String constant designating no time information. Current value of
			this constant is <b>NULL</b>.
			*/
			static String NULL_DATE_FORMAT;

			/**
			String constant designating relative time. Current value of
			this constant is <b>RELATIVE</b>.
			*/
			static String RELATIVE_TIME_DATE_FORMAT;

			static String DATE_FORMAT_OPTION;
			static String TIMEZONE_OPTION;

		private:
			String timeZone;
			String dateFormatOption;
			
		protected:
			DateFormat * dateFormat;

		public:
			DateLayout();
			virtual ~DateLayout();
		/**
		Sets the DateFormat used to format date and time in the time zone
		determined by <code>timeZone</code> parameter. The 
		helpers::DateFormat DateFormat used
		will depend on the <code>dateFormatType</code>.

		<p>The recognized types are #NULL_DATE_FORMAT, 
		#RELATIVE_TIME_DATE_FORMAT, 
		helpers::AbsoluteTimeDateFormat#ABS_TIME_DATE_FORMAT,
		helpers::AbsoluteTimeDateFormat#DATE_AND_TIME_DATE_FORMAT and 
		helpers::AbsoluteTimeDateFormat#ISO8601_DATE_FORMAT. If the
		<code>dateFormatType</code> is not one of the above, then the
		argument is assumed to be a date pattern for 
		helpers::DateFormat.
		*/
  			virtual void activateOptions();
			
			virtual void setOption(const String& option, const String& value);

		/**
		The value of the <b>DateFormat</b> option should be either an
		argument to the constructor of helpers::DateFormat or one of
		the srings <b>"NULL"</b>, <b>"RELATIVE"</b>, <b>"ABSOLUTE"</b>,
		<b>"DATE"</b> or <b>"ISO8601</b>.
		*/
			inline void setDateFormat(const String& dateFormat)
				{ this->dateFormatOption = dateFormat; }

		/**
		Returns value of the <b>DateFormat</b> option.
		*/
			inline const String& getDateFormat() const
				{ return dateFormatOption; }

		/**
		The <b>TimeZoneID</b> option is a time zone ID string in the format
		expected by the <code>locale</code> C++ standard class.
		*/
			inline void setTimeZone(const String& timeZone)
				{ this->timeZone = timeZone; }

		/**
		Returns value of the <b>TimeZone</b> option.
		*/
			inline const String& getTimeZone() const
				{ return timeZone; }
				
			void formatDate(ostream &os, const spi::LoggingEventPtr& event);
 		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_DATE_LAYOUT_H
