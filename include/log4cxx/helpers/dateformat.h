/*
 * Copyright 2003,2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#ifndef _LOG4CXX_HELPERS_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_DATE_FORMAT_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/timezone.h>

namespace log4cxx
{
	namespace helpers
	{
		/** 
		Concrete class for formatting and parsing dates in a 
		locale-sensitive manner.
		
		Date and time formats are specified by date and time pattern strings.
		Within date and time pattern strings, letters from 'A' to 'Z' and from
		'a' to 'z', preceded by the character '%', are interpreted as pattern
		letters representing the components	of a date or time string
		
		The following pattern letters are defined:
		- \%a -- Abbreviated weekday name
		- \%A -- Full weekday name
		- \%b -- Abbreviated month name
		- \%B -- Full month name
		- \%c -- Standard date and time string
		- \%d -- Day of month as a decimal(1-31)
		- \%H -- Hour(0-23)
		- \%I -- Hour(1-12)
		- \%j -- Day of year as a decimal(1-366)
		- \%m -- Month as decimal(1-12)
		- \%M -- Minute as decimal(00-59)
		- \%p -- Locale's equivalent of AM or PM
		- \%Q -- Millisecond as decimal (000-999)
		- \%S -- Second as decimal(00-59)
		- \%U -- Week of year, Sunday being first day(0-53)
		- \%w -- Weekday as a decimal(0-6, Sunday being 0)
		- \%W -- Week of year, Monday being first day(0-53)
		- \%x -- Standard date string
		- \%X -- Standard time string
		- \%y -- Year in decimal without century(0-99)
		- \%Y -- Year including century as decimal
		- \%Z -- Time zone name
		- \%\% -- The percent sign
		*/
		class LOG4CXX_EXPORT DateFormat
		{
		public:
			/**
			Constructs a DateFormat using the given pattern and the default
			time zone.
			
			@param pattern the pattern describing the date and time format
			*/
			DateFormat(const String& pattern);
			
			/**
			Constructs a DateFormat using the given pattern and the given
			time zone.
			
			@param pattern the pattern describing the date and time format
			@param timeZone the timeZone to be used in the formatting
			operations.
			*/
			DateFormat(const String& pattern, const TimeZonePtr& timeZone);
			virtual ~DateFormat();
			
			/**
			Formats a Date into a date/time string.
			
			@param toAppendTo the stream for the returning date/time string.
			
			@param time the time value (in milliseconds since
			January 1, 1970 00:00:00 GMT) to be formatted into a time string.
			*/
			virtual void format(ostream& toAppendTo, int64_t time) const;
			
			/** 
			Formats a Date into a date/time string.
			
			@param time the time value (in milliseconds since
			January 1, 1970 00:00:00 GMT) to be formatted into a time string.
			
			@return the formatted time string.
			*/
			String format(int64_t time) const;

		protected:
			TimeZonePtr timeZone;
			String dateFormat;
		};
	}  // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPERS_DATE_FORMAT_H
