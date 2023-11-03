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

#ifndef _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H

#include <log4cxx/helpers/dateformat.h>
#include <vector>
#include <time.h>

#include <locale>

using std::locale;

namespace LOG4CXX_NS
{
namespace helpers
{
namespace SimpleDateFormatImpl
{
class PatternToken;
}

LOG4CXX_LIST_DEF(PatternTokenList, LOG4CXX_NS::helpers::SimpleDateFormatImpl::PatternToken*);


/**
 * Concrete class for converting and formatting a date/time
 * in a locale-sensitive manner.
 *
 * Specifier | Date/time component
 * --------- | ---------------------
 * G | era
 * y | year
 * M | month number
 * MMM | abbreviated month name
 * MMMM | full month name
 * w | week in year
 * W | week in month
 * D | day in year
 * d | day in month
 * EEE | abbreviated day name
 * EEEE | full day name
 * a | AM or PM
 * H | hour 0 - 23
 * k | hour 1 - 24
 * K | hour 0 - 11
 * h | hour 1 - 12
 * m | minute
 * s | second
 * S | millisecond
 * z | time zone identifier
 * Z | RFC822 time zone
 */
class LOG4CXX_EXPORT SimpleDateFormat : public DateFormat
{
	public:
		/**
		 * A time converter and formatter using \c pattern and the default std::locale.
		 *
		 * @param pattern the specifiers describing the date and time format
		 */
		SimpleDateFormat(const LogString& pattern);
		/**
		 * A time converter and formatter using \c pattern and \c locale.
		 *
		 * @param pattern the specifiers describing the date and time format
		 * @param locale the user-preferred set of immutable facets
		 */
		SimpleDateFormat(const LogString& pattern, const std::locale* locale);
		~SimpleDateFormat();

		virtual void format(LogString& s,
			log4cxx_time_t tm,
			LOG4CXX_NS::helpers::Pool& p) const;

		/**
		 * Set time zone.
		 * @param zone new time zone.
		 */
		void setTimeZone(const TimeZonePtr& zone);

	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(SimpleDateFormatPrivate, m_priv)

		static void addToken(const logchar spec, const int repeat, const std::locale* locale, PatternTokenList& pattern);
		static void parsePattern(const LogString& spec, const std::locale* locale, PatternTokenList& pattern);
};


}  // namespace helpers
} // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H
