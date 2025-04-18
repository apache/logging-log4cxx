/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/logstring.h>
#include <log4cxx/pattern/datepatternconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/helpers/absolutetimedateformat.h>
#include <log4cxx/helpers/datetimedateformat.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/strftimedateformat.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/private/patternconverter_priv.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::pattern;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

struct DatePatternConverter::DatePatternConverterPrivate : public PatternConverterPrivate
{
	DatePatternConverterPrivate( const LogString& name, const LogString& style, DateFormatPtr _df ):
		PatternConverterPrivate(name, style),
		df(_df) {}
	/**
	 * Date format.
	 */
	LOG4CXX_NS::helpers::DateFormatPtr df;
};

#define priv static_cast<DatePatternConverterPrivate*>(m_priv.get())

IMPLEMENT_LOG4CXX_OBJECT(DatePatternConverter)

DatePatternConverter::DatePatternConverter(
	const std::vector<LogString>& options) :
	LoggingEventPatternConverter (std::make_unique<DatePatternConverterPrivate>(LOG4CXX_STR("Class Name"),
			LOG4CXX_STR("class name"), getDateFormat(options)))
{
}

DatePatternConverter::~DatePatternConverter() {}

DateFormatPtr DatePatternConverter::getDateFormat(const OptionsList& options)
{
	DateFormatPtr df;
	int maximumCacheValidity = 1000000;

	if (options.size() == 0)
	{
		df = std::make_shared<ISO8601DateFormat>();
	}
	else
	{
		LogString dateFormatStr(options[0]);

		if (dateFormatStr.empty() ||
			StringHelper::equalsIgnoreCase(dateFormatStr,
				LOG4CXX_STR("ISO8601"), LOG4CXX_STR("iso8601")))
		{
			df = std::make_shared<ISO8601DateFormat>();
		}
		else if (StringHelper::equalsIgnoreCase(dateFormatStr,
				LOG4CXX_STR("ABSOLUTE"), LOG4CXX_STR("absolute")))
		{
			df = std::make_shared<AbsoluteTimeDateFormat>();
		}
		else if (StringHelper::equalsIgnoreCase(dateFormatStr,
				LOG4CXX_STR("DATE"), LOG4CXX_STR("date")))
		{
			df = std::make_shared<DateTimeDateFormat>();
		}
		else
		{
			if (dateFormatStr.find(0x25 /*'%'*/) == std::string::npos)
			{
				try
				{
					df = std::make_shared<SimpleDateFormat>(dateFormatStr);
					maximumCacheValidity =
						CachedDateFormat::getMaximumCacheValidity(dateFormatStr);
				}
				catch (std::exception& e)
				{
					df = std::make_shared<ISO8601DateFormat>();
					LogLog::warn(((LogString)
							LOG4CXX_STR("Could not instantiate SimpleDateFormat with pattern "))
						+ dateFormatStr, e);
				}
			}
			else
			{
				df = std::make_shared<StrftimeDateFormat>(dateFormatStr);
			}
		}

		if (options.size() >= 2)
		{
			TimeZonePtr tz;
			try
			{
				tz = TimeZone::getTimeZone(options[1]);
			}
			catch (std::exception& e)
			{
				LogLog::warn(LOG4CXX_STR("Invalid time zone: ") + options[1], e);
			}

			if (tz)
			{
				df->setTimeZone(tz);
			}
		}
	}

	if (maximumCacheValidity > 0)
	{
		df = std::make_shared<CachedDateFormat>(df, maximumCacheValidity);
	}

	return df;
}

PatternConverterPtr DatePatternConverter::newInstance(
	const std::vector<LogString>& options)
{
	return std::make_shared<DatePatternConverter>(options);
}

void DatePatternConverter::format(
	const LoggingEventPtr& event,
	LogString& toAppendTo,
	Pool& p) const
{
	priv->df->format(toAppendTo, event->getTimeStamp(), p);
}

/**
 * {@inheritDoc}
 */
void DatePatternConverter::format(
	const ObjectPtr& obj,
	LogString& toAppendTo,
	Pool& p) const
{
	DatePtr date = LOG4CXX_NS::cast<Date>(obj);

	if (date != NULL)
	{
		format(date, toAppendTo, p);
	}
	else
	{
		LoggingEventPtr event = LOG4CXX_NS::cast<LoggingEvent>(obj);

		if (event != NULL)
		{
			format(event, toAppendTo, p);
		}
	}
}

/**
 * Append formatted date to string buffer.
 * @param date date
 * @param toAppendTo buffer to which formatted date is appended.
 */
void DatePatternConverter::format(
	const DatePtr& date,
	LogString& toAppendTo,
	Pool& p) const
{
	priv->df->format(toAppendTo, date->getTime(), p);
}
