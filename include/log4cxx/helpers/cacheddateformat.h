/*
 * Copyright 2004 The Apache Software Foundation.
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

#ifndef _LOG4CXX_HELPERS_CACHED_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_CACHED_DATE_FORMAT_H

#include <log4cxx/helpers/dateformat.h>

namespace log4cxx
{
        namespace helpers
        {
          class LOG4CXX_EXPORT CachedDateFormat : public DateFormat {
          public:
               CachedDateFormat(DateFormatPtr& baseFormatter);

               virtual void format(LogString &s,
                   log4cxx_time_t date,
                   apr_pool_t* p) const;
               virtual void setTimeZone(const TimeZonePtr& zone);
               virtual void numberFormat(LogString& s,
                                         long n,
                                         apr_pool_t* p) const;


          private:
          /**
           * Finds start of millisecond field in formatted time.
           * @param time long time, must be integral number of seconds
           * @param formatted String corresponding formatted string
           * @param zeroDigit char digit used to represent zero
           * @param formatter DateFormat date format
           * @return int position in string of first digit of milliseconds,
           *    -1 indicates no millisecond field, -2 indicates unrecognized
           *    field (likely RelativeTimeDateFormat)
           */
               static int findMillisecondStart(const log4cxx_time_t time,
                                          const LogString& formatted,
                                          const logchar zeroDigit,
                                          const logchar nineDigit,
                                          const DateFormatPtr& formatter,
                                          apr_pool_t* p);

               DateFormatPtr formatter;
               mutable int millisecondStart;
               mutable LogString cache;
               mutable log4cxx_time_t previousTime;
               logchar zeroDigit;
               logchar nineDigit;
                           enum {
                   UNRECOGNIZED_MILLISECOND_PATTERN = -2,
                                           NO_MILLISECOND_PATTERN = -1 };
          };



        }  // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H
