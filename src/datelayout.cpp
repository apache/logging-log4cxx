/***************************************************************************
                          datelayout.cpp  -  description
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

#include <log4cxx/helpers/datelayout.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/dateformat.h>
#include <log4cxx/helpers/relativetimedateformat.h>
#include <log4cxx/helpers/absolutetimedateformat.h>
#include <log4cxx/helpers/datetimedateformat.h>
#include <log4cxx/helpers/iso8601dateformat.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

String DateLayout::NULL_DATE_FORMAT = _T("NULL");
String DateLayout::RELATIVE_TIME_DATE_FORMAT = _T("RELATIVE");

String DateLayout::DATE_FORMAT_OPTION = _T("DateFormat");
String DateLayout::TIMEZONE_OPTION = _T("TimeZone");

DateLayout::DateLayout() : dateFormat(0)
{
}

DateLayout::~DateLayout()
{
	if (dateFormat != 0)
	{
		delete dateFormat;
	}
}

void DateLayout::setOption(const String& option, const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, DATE_FORMAT_OPTION))
	{
		dateFormatOption = StringHelper::toUpperCase(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, TIMEZONE_OPTION))
	{
		timeZone = value;
	}
}

void DateLayout::activateOptions()
{
	if (dateFormat != 0)
	{
		delete dateFormat;
	}
	
	if(dateFormatOption.empty())
	{
		dateFormat = 0;
	}
	else if(StringHelper::equalsIgnoreCase(dateFormatOption,
		NULL_DATE_FORMAT))
	{
		dateFormat = 0;
	}
	else if(StringHelper::equalsIgnoreCase(dateFormatOption,
		RELATIVE_TIME_DATE_FORMAT))
	{
		dateFormat =  new RelativeTimeDateFormat();
	}
	else if(StringHelper::equalsIgnoreCase(dateFormatOption,
		AbsoluteTimeDateFormat::ABS_TIME_DATE_FORMAT))
	{
		dateFormat =  new AbsoluteTimeDateFormat(timeZone);
	}
	else if(StringHelper::equalsIgnoreCase(dateFormatOption,
		AbsoluteTimeDateFormat::DATE_AND_TIME_DATE_FORMAT))
	{
		dateFormat =  new DateTimeDateFormat(timeZone);
	}
	else if(StringHelper::equalsIgnoreCase(dateFormatOption,
		AbsoluteTimeDateFormat::ISO8601_DATE_FORMAT))
	{
		dateFormat =  new ISO8601DateFormat(timeZone);
	}
	else
	{
		dateFormat = new DateFormat(dateFormatOption, timeZone);
	}
}

void DateLayout::formatDate(ostream &os, const spi::LoggingEvent& event)
{
	if(dateFormat != 0)
	{
		dateFormat->format(os, event.getTimeStamp());
		os.put(_T(' '));
	}
}

