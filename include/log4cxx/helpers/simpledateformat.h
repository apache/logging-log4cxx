/*
 * Copyright 2004-2005 The Apache Software Foundation.
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

#ifndef _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H

#include <log4cxx/helpers/dateformat.h>
#include <vector>
#include <locale>
#include <time.h>

namespace log4cxx
{
        namespace helpers
        {

          /**
          Concrete class for formatting and parsing dates in a
          locale-sensitive manner.

          */
          class LOG4CXX_EXPORT SimpleDateFormat : public DateFormat
          {
          public:
                  /**
                  Constructs a DateFormat using the given pattern and the default
                  time zone.

                  @param pattern the pattern describing the date and time format
                  */
                  SimpleDateFormat(const LogString& pattern);
                  SimpleDateFormat(const LogString& pattern, const std::locale& locale);
                  ~SimpleDateFormat();

                  virtual void format(LogString& s,
                                      log4cxx_time_t time,
                                      log4cxx::helpers::Pool& p) const;

                  /**
                  *    Set time zone.
                  * @param zone new time zone.
                  */
                  void setTimeZone(const TimeZonePtr& zone);


                  /**
                  * Abstract inner class representing one format token
                  * (one or more instances of a character).
                  */
                  class PatternToken {
                  public:
                       /**
                        *   Constructor.
                        */
                       PatternToken();
                       /**
                       * Destructor.
                       */
                       virtual ~PatternToken();

                       /**
                       * Sets the time zone.
                       * @param zone new time zone.
                       */
                       virtual void setTimeZone(const TimeZonePtr& zone);

                      /**
                      * Appends the formatted content to the string.
                      * @param s string to which format contribution is appended.
                      * @param date exploded date/time.
                      * @param p memory pool.
                      */
                       virtual void format(std::wstring& s,
                                           const apr_time_exp_t& date,
                                           log4cxx::helpers::Pool& p) const = 0;

                  protected:
                        static void renderFacet(const std::locale& locale,
                                             std::wostream& buffer,
                                             const tm* time,
                                             const wchar_t spec);

                  private:
                      /**
                      *    Private copy constructor.
                      */
                       PatternToken(const PatternToken&);
                       /**
                       * Private assignment operator.
                       */
                       PatternToken& operator=(const PatternToken&);
                  };



          private:
                  /**
                  *    Time zone.
                  */
                  TimeZonePtr timeZone;
                  /**
                  * List of tokens.
                  */
                  typedef std::vector<PatternToken*> PatternTokenList;
                  PatternTokenList pattern;
                  static void addToken(const wchar_t spec,
                                                  const int repeat,
                                                  const std::locale& locale,
                                                  PatternTokenList& pattern);
                  static void parsePattern(const LogString& fmt,
                          const std::locale& locale,
                          PatternTokenList& pattern);
          };


        }  // namespace helpers
} // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H
