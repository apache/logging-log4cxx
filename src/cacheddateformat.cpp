/*
 * Copyright 1999,2004 The Apache Software Foundation.
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

#include <log4cxx/helpers/cacheddateformat.h>

#define INT64_C(x) x##LL

#include <apr-1/apr_time.h>
#include <apr-1/apr_pools.h>

using namespace log4cxx::helpers;

CachedDateFormat::CachedDateFormat(DateFormatPtr& formatter) :
    formatter(formatter) {

    apr_time_t nowTime = apr_time_now();
    previousTime = (nowTime / APR_USEC_PER_SEC) * APR_USEC_PER_SEC;
    //
    //    if now is before 1970 and previousTime was truncated forward
    //       set cached time back one second
    if (nowTime - previousTime < 0) {
      previousTime -= APR_USEC_PER_SEC;
    }
    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    formatter->format(cache, previousTime, p);
    std::string digits;
    formatter->numberFormat(digits, 90, p);
    nineDigit = digits[0];
    zeroDigit = digits[1];
    millisecondStart = findMillisecondStart(previousTime,
           cache,
           zeroDigit,
           nineDigit,
           formatter,
           p);
    apr_pool_destroy(p);
}

int CachedDateFormat::findMillisecondStart(const apr_time_t time,
                                          const std::string& formatted,
                                          char zeroDigit,
                                          char nineDigit,
                                          const DateFormatPtr& formatter,
                                          apr_pool_t* p) {
      std::string plus987;
      formatter->format(plus987, time + 987000, p);
      //
      //    find first difference between values
      //
      for (int i = 0; i < formatted.length(); i++) {
        if (formatted[i] != plus987[i]) {
          if (formatted[i] == zeroDigit && plus987[i] == nineDigit) {
            return i;
          } else {
            return UNRECOGNIZED_MILLISECOND_PATTERN;
          }
        }
      }
    return NO_MILLISECOND_PATTERN;
}


  /**
   * Converts a Date utilizing a previously converted
   * value if possible.

     @param date the date to format
     @param sbuf the string buffer to write to
     @param fieldPosition remains untouched
   */
void CachedDateFormat::format(std::string& s, apr_time_t date, apr_pool_t* p) const {
    if (millisecondStart == UNRECOGNIZED_MILLISECOND_PATTERN) {
      formatter->format(s, date, p);
      return;
    }
    std::string& mutableCache = LOG4CXX_ACCESS_MUTABLE(cache, CachedDateFormat);
    if (date < previousTime + APR_USEC_PER_SEC && date >= previousTime) {
      if (millisecondStart >= 0) {
        mutableCache.erase(millisecondStart, 3);
        int millis = apr_time_as_msec(date - previousTime);
        int cacheLength = cache.length();
        formatter->numberFormat(mutableCache, millis, p);
        int milliLength = cache.length() - cacheLength;
        //
        //   if it didn't belong at the end, then move it
        if (cacheLength != millisecondStart) {
          std::string milli = cache.substr(cacheLength);
          mutableCache.erase(mutableCache.begin() + cacheLength, mutableCache.end());
          mutableCache.insert(millisecondStart, milli);
        }
        if (milliLength < 3) {
           mutableCache.insert(millisecondStart,
                 3 - milliLength, zeroDigit);
        }
      }
    } else {
      apr_time_t prev = (date / APR_USEC_PER_SEC) * APR_USEC_PER_SEC;
      //
      //   if earlier than 1970 and rounded toward 1970
      //      then move back one second
      if (date - prev < 0) {
        prev -= APR_USEC_PER_SEC;
      }
      LOG4CXX_ACCESS_MUTABLE(previousTime, CachedDateFormat) = prev;
      int prevLength = cache.length();
      mutableCache.erase(mutableCache.begin(), mutableCache.end());
      formatter->format(mutableCache, date, p);
      //
      //   if the length changed then
      //      recalculate the millisecond position
      if (cache.length() != prevLength) {
        std::string formattedPreviousTime;
        formatter->format(formattedPreviousTime, previousTime, p);
        LOG4CXX_ACCESS_MUTABLE(millisecondStart, CachedDateFormat) =
            findMillisecondStart(previousTime,
                                 formattedPreviousTime,
                                 zeroDigit,
                                 nineDigit,
                                 formatter, p);
      }
    }
    s.append(cache);
  }


  /**
   * Set timezone.
   *
   * @remarks Setting the timezone using getCalendar().setTimeZone()
   * will likely cause caching to misbehave.
   * @param timeZone TimeZone new timezone
   */
void CachedDateFormat::setTimeZone(const TimeZonePtr& timeZone) {
    formatter->setTimeZone(timeZone);
    int prevLength = cache.length();
    cache.erase(cache.begin(), cache.end());
    apr_pool_t *p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    formatter->format(cache, previousTime, p);
    //
    //   if the length changed then
    //      recalculate the millisecond position
    if (cache.length() != prevLength) {
      millisecondStart = findMillisecondStart(previousTime,
                                              cache,
                                              zeroDigit,
                                              nineDigit,
                                              formatter, p);
    }
    apr_pool_destroy(p);
  }


void CachedDateFormat::numberFormat(std::string& s, long n, apr_pool_t* p) const {
  formatter->numberFormat(s, n, p);
}
