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

DateLayout::DateLayout(const String& dateFormatOption) :
   dateFormat(0), timeZoneID(), dateFormatOption(dateFormatOption)
{
}

DateLayout::~DateLayout()
{
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
          static const String NULL_DATE_FORMAT("NULL");
          static const String RELATIVE_TIME_DATE_FORMAT("RELATIVE");
          static const String ABSOLUTE_TIME_DATE_FORMAT("ABSOLUTE");
          static const String DATE_TIME_DATE_FORMAT("DATE");
          static const String ISO8601_DATE_FORMAT("ISO601");

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
                  ABSOLUTE_TIME_DATE_FORMAT))
          {
                  dateFormat =  new AbsoluteTimeDateFormat();
          }
          else if(StringHelper::equalsIgnoreCase(dateFormatOption,
                  DATE_TIME_DATE_FORMAT))
          {
                  dateFormat =  new DateTimeDateFormat();
          }
          else if(StringHelper::equalsIgnoreCase(dateFormatOption,
                  ISO8601_DATE_FORMAT))
          {
                  dateFormat =  new ISO8601DateFormat();
          }
          else
          {
                  dateFormat = new SimpleDateFormat(dateFormatOption);
          }
	}
        if (dateFormat != NULL) {
           if (timeZoneID.empty()) {
              dateFormat->setTimeZone(TimeZone::getDefault());
           } else {
              dateFormat->setTimeZone(TimeZone::getTimeZone(timeZoneID));
           }
        }
}


void DateLayout::formatDate(std::string &s,
                            const spi::LoggingEventPtr& event,
                            apr_pool_t* p) const {

	if(dateFormat != 0)
	{
                dateFormat->format(s, event->getTimeStamp(), p);
                s.append(1, ' ');
	}
}

