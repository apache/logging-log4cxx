/***************************************************************************
                          datetimedateformat.h  -  description
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

#ifndef _LOG4CXX_HELPERS_DATE_TIME_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_DATE_TIME_DATE_FORMAT_H

#include <log4cxx/helpers/dateformat.h>

namespace log4cxx
{
	namespace helpers
	{
		/**
		Formats a date in the format "\%d \%b \%Y \%H:\%M:\%S" for example,
	   "06 Nov 1994 15:49:37".
		*/
		class DateTimeDateFormat : public DateFormat
		{
		public:
			DateTimeDateFormat(const tstring& timeZone = _T(""))
			 : DateFormat(_T("%d %b %Y %H:%M:%S"), timeZone) {}
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_DATE_TIME_DATE_FORMAT_H
