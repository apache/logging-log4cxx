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

#include <log4cxx/helpers/datelayout.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/dateformat.h>
#include <log4cxx/helpers/relativetimedateformat.h>
#include <log4cxx/helpers/absolutetimedateformat.h>
#include <log4cxx/helpers/datetimedateformat.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/timezone.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

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

  static String DATE_FORMAT_OPTION("DateFormat");
  static String TIMEZONE_OPTION("TimeZone");

	if (StringHelper::equalsIgnoreCase(option, DATE_FORMAT_OPTION))
	{
		dateFormatOption = StringHelper::toUpperCase(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, TIMEZONE_OPTION))
	{
		timeZoneID = value;
	}
}

void DateLayout::activateOptions()
{
	if(!dateFormatOption.empty())
	{
		if (timeZoneID.empty())
		{
			setDateFormat(dateFormatOption, TimeZone::getDefault());
		}
		else
		{
			setDateFormat(dateFormatOption, TimeZone::getTimeZone(timeZoneID));
		}
	}
}

void DateLayout::setDateFormat(const String& dateFormatType,
	const TimeZonePtr& timeZone)
{
	if (dateFormat != 0)
	{
		delete dateFormat;
	}

        static const String NULL_DATE_FORMAT("NULL");
        static const String RELATIVE_TIME_DATE_FORMAT("RELATIVE");

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
		AbsoluteTimeDateFormat::getAbsTimeDateFormat()))
	{
		dateFormat =  new AbsoluteTimeDateFormat(timeZone);
	}
	else if(StringHelper::equalsIgnoreCase(dateFormatOption,
		AbsoluteTimeDateFormat::getDateAndTimeDateFormat()))
	{
		dateFormat =  new DateTimeDateFormat(timeZone);
	}
	else if(StringHelper::equalsIgnoreCase(dateFormatOption,
		AbsoluteTimeDateFormat::getIso8601DateFormat()))
	{
		dateFormat =  new ISO8601DateFormat(timeZone);
	}
	else
	{
		dateFormat = new DateFormat(dateFormatOption, timeZone);
	}
}

void DateLayout::formatDate(ostream &os, const spi::LoggingEventPtr& event) const
{
	if(dateFormat != 0)
	{
		dateFormat->format(os, event->getTimeStamp());
		os.put(_T(' '));
	}
}

