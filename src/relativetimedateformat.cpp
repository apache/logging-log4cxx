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

#include <log4cxx/helpers/relativetimedateformat.h>
#include <log4cxx/spi/loggingevent.h>

#include <apr_time.h>
#include <apr_strings.h>

#include <limits.h>


log4cxx::helpers::RelativeTimeDateFormat::RelativeTimeDateFormat()
 : DateFormat(), startTime(log4cxx::spi::LoggingEvent::getStartTime())
{
}

void log4cxx::helpers::RelativeTimeDateFormat::format(
    std::string &s,
    apr_time_t date,
    apr_pool_t* p) const {
    apr_interval_time_t interval = date - startTime;
    apr_interval_time_t ms = interval / 1000;
    if (ms >= INT_MIN && ms <= INT_MAX) {
      s.append(apr_itoa(p, ms));
    } else {
      const apr_int64_t BILLION = 1000000000;
      s.append(apr_itoa(p, ms / BILLION));
      char* lower = apr_itoa(p, ms % BILLION);
      int fill = 9 - strlen(lower);
      int start = 0;
      if (ms < 0) {
        fill++;
        start++;
      }
      if (fill > 0) {
        s.append(fill, '0');
      }
      s.append(lower + start);
    }
}
