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
#include <iomanip> // for setw & setfill

using namespace log4cxx;
using namespace log4cxx::helpers;

String AbsoluteTimeDateFormat::ISO8601_DATE_FORMAT = _T("ISO8601");
String AbsoluteTimeDateFormat::ABS_TIME_DATE_FORMAT = _T("ABSOLUTE");
String AbsoluteTimeDateFormat::DATE_AND_TIME_DATE_FORMAT = _T("DATE");

DateFormat::DateFormat(const String& dateFormat, const String& timeZone)
 : dateFormat(dateFormat), timeZone(timeZone)
{
	size_t pos = this->dateFormat.find(_T("%Q"));
	if (pos != String::npos)
	{
		this->dateFormat = this->dateFormat.substr(0, pos) +
			_T("%") + this->dateFormat.substr(pos);
	}
}

void DateFormat::format(ostream& os, int64_t timeMillis)
{
    TCHAR buffer[255];

	if (!timeZone.empty())
	{
		USES_CONVERSION;
		::setenv("TZ", T2A(timeZone.c_str()), 1);
	}

	time_t time = (time_t)(timeMillis/1000);
	const tm * tm = ::localtime(&time);

#ifdef UNICODE
	size_t len = ::wcsftime(buffer, 255, dateFormat.c_str(), tm);
#else
	size_t len = ::strftime(buffer, 255, dateFormat.c_str(), tm);
#endif

	buffer[len] = '\0';
	String result(buffer);

	size_t pos = result.find(_T("%Q"));
	if (pos != String::npos)
	{
		os << result.substr(0, pos)
		   << std::setw(3) << std::setfill(_T('0')) << (long)(timeMillis % 1000)
		   << result.substr(pos + 2);
	}
	else
	{
		os << result;
	}
}
