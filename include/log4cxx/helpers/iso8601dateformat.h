/***************************************************************************
                          iso8601dateformat.h  -  description
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

#ifndef _LOG4CXX_HELPERS_ISO_8601_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_ISO_8601_DATE_FORMAT_H

#include <log4cxx/helpers/dateformat.h>

namespace log4cxx
{
	namespace helpers
	{
		/**
		Formats a date in the format "%Y-%m-%d %H:%M:%S,%Q" for example
		"1999-11-27 15:49:37,459".

		<p>Refer to the <a>
		href=http://www.cl.cam.ac.uk/~mgk25/iso-time.html>summary of the
		International Standard Date and Time Notation</a> for more
		information on this format.
		*/
		class ISO8601DateFormat : public DateFormat
		{
		public:
			ISO8601DateFormat(const tstring& timeZone = _T(""))
			 : DateFormat(_T("%Y-%m-%d %H:%M:%S,%Q"), timeZone) {}
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_ISO_8601_DATE_FORMAT_H

