/***************************************************************************
                          absolutetimedateformat.h  -  description
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

#ifndef _LOG4CXX_HELPERS_ABSOLUTE_TIME_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_ABSOLUTE_TIME_DATE_FORMAT_H

#include <log4cxx/helpers/dateformat.h>

namespace log4cxx
{
	namespace helpers
	{
		/**
		Formats a date in the format "%H:%M:%S" for example,
		"15:49:37".
		*/
		class AbsoluteTimeDateFormat : public DateFormat
		{
		public:
			/**
			string constant used to specify
			ISO8601DateFormat in layouts. Current
			value is <b>ISO8601</b>.
			*/
			static String ISO8601_DATE_FORMAT;

			/**
			String constant used to specify
			AbsoluteTimeDateFormat in layouts. Current
			value is <b>ABSOLUTE</b>.  */
			static String ABS_TIME_DATE_FORMAT;

			/**
			String constant used to specify
			DateTimeDateFormat in layouts.  Current
			value is <b>DATE</b>.
			*/
			static String DATE_AND_TIME_DATE_FORMAT;

			AbsoluteTimeDateFormat(const String& timeZone = _T(""))
			: DateFormat(_T("%H:%M:%S"), timeZone) {}
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_ABSOLUTE_TIME_DATE_FORMAT_H
