/***************************************************************************
                          dateformat.cpp  -  description
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

#include <log4cxx/helpers/dateformat.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/absolutetimedateformat.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

tstring AbsoluteTimeDateFormat::ISO8601_DATE_FORMAT = _T("ISO8601");
tstring AbsoluteTimeDateFormat::ABS_TIME_DATE_FORMAT = _T("ABSOLUTE");
tstring AbsoluteTimeDateFormat::DATE_AND_TIME_DATE_FORMAT = _T("DATE");

DateFormat::DateFormat(const tstring& dateFormat, const tstring& timeZone)
 : dateFormat(dateFormat), timeZone(timeZone)
{
}

void DateFormat::format(tostream& os, time_t time)
{
	typedef tostream::char_type char_type;
	typedef tostream::traits_type traits_type;
	typedef std::ostreambuf_iterator<char_type, traits_type> iterator_type;
	typedef std::time_put< char_type, iterator_type > facet_type;

	const tm * tm = gmtime(&time);

	if (timeZone.empty())
	{
		std::locale loc = os.getloc();

#ifdef WIN32
		const facet_type& facet = std::use_facet<facet_type>(loc, 0, true);
		 facet.put(os,os,tm,dateFormat.c_str(), dateFormat.c_str() +
			 dateFormat.size());
#else
		const facet_type& facet = std::use_facet<facet_type>(loc);
		 facet.put(os,os,_T(' '),tm,dateFormat.c_str(), dateFormat.c_str() +
			 dateFormat.size());
#endif
	}
	else
	{
		USES_CONVERSION;
		std::locale loc(T2A(timeZone.c_str()));

#ifdef WIN32
		const facet_type& facet = std::use_facet<facet_type>(loc, 0, true);
		 facet.put(os,os,tm,dateFormat.c_str(), dateFormat.c_str() +
			 dateFormat.size());
#else
		const facet_type& facet = std::use_facet<facet_type>(loc);
		 facet.put(os,os,_T(' '),tm,dateFormat.c_str(), dateFormat.c_str() +
			 dateFormat.size());
#endif
	}
}
