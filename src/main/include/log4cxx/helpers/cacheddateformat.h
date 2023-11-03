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

#ifndef _LOG4CXX_HELPERS_CACHED_DATE_FORMAT_H
#define _LOG4CXX_HELPERS_CACHED_DATE_FORMAT_H

#include <log4cxx/helpers/dateformat.h>

namespace LOG4CXX_NS
{
namespace pattern
{
class LOG4CXX_EXPORT CachedDateFormat : public LOG4CXX_NS::helpers::DateFormat
{
	public:
		enum
		{
			/*
			 *  Constant used to represent that there was no change
			 *  observed when changing the millisecond count.
			 */
			NO_MILLISECONDS = -2,
			/*
			 *  Constant used to represent that there was an
			 *  observed change, but was an expected change.
			 */
			UNRECOGNIZED_MILLISECONDS = -1
		};

	private:
		/**
		 *  Supported digit set.  If the wrapped DateFormat uses
		 *  a different unit set, the millisecond pattern
		 *  will not be recognized and duplicate requests
		 *  will use the cache.
		 */
		static const logchar digits[];


		/**
		 * First magic number (in microseconds) used to detect
		 * the millisecond position.
		 */
		static const int magic1;


		/**
		 *  Expected representation of first magic number in milliseconds.
		 */
		static const logchar magicString1[];


		/**
		 * Second magic number (in microseconds) used to detect
		 * the millisecond position.
		 */
		static const int magic2;


		/**
		 *  Expected representation of second magic number in milliseconds.
		 */
		static const logchar magicString2[];


		/**
		 *  Expected representation of 0 milliseconds.
		 */
		static const logchar zeroString[];

		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(CachedDateFormatPriv, m_priv)

	public:
		/**
		 *  Creates a new CachedDateFormat object.
		 *  @param dateFormat Date format, may not be null.
		 *  @param expiration maximum cached range in microseconds.
		 *    If the dateFormat is known to be incompatible with the
		 *      caching algorithm, use a value of 0 to totally disable
		 *      caching or 1 to only use cache for duplicate requests.
		 */
		CachedDateFormat(const LOG4CXX_NS::helpers::DateFormatPtr& dateFormat, int expiration);
		~CachedDateFormat();

		/**
		 * Finds start of millisecond field in formatted time.
		 * @param time long time, must be integral number of seconds
		 * @param formatted String corresponding formatted string
		 * @param formatter DateFormat date format
		 * @param pool pool.
		 * @return int position in string of first digit of milliseconds,
		 *    -1 indicates no millisecond field, -2 indicates unrecognized
		 *    field (likely RelativeTimeDateFormat)
		 */
		static int findMillisecondStart(
			log4cxx_time_t time, const LogString& formatted,
			const LOG4CXX_NS::helpers::DateFormatPtr& formatter,
			LOG4CXX_NS::helpers::Pool& pool);

		/**
		 * Formats a Date into a date/time string.
		 *
		 *  @param date the date to format.
		 *  @param sbuf the string buffer to write to.
		 *  @param p memory pool.
		 */
		virtual void format(LogString& sbuf,
			log4cxx_time_t date,
			LOG4CXX_NS::helpers::Pool& p) const;

	private:
		/**
		 *   Formats a count of milliseconds (0-999) into a numeric representation.
		 *   @param millis Millisecond coun between 0 and 999.
		 *   @buf String buffer, may not be null.
		 *   @offset Starting position in buffer, the length of the
		 *       buffer must be at least offset + 3.
		 */
		static void millisecondFormat(int millis,
			LogString& buf,
			int offset);


	public:
		/**
		 * Set timezone.
		 *
		 * @remarks Setting the timezone using getCalendar().setTimeZone()
		 * will likely cause caching to misbehave.
		 * @param zone TimeZone new timezone
		 */
		virtual void setTimeZone(const LOG4CXX_NS::helpers::TimeZonePtr& zone);

		/**
		* Format an integer consistent with the format method.
		* @param s string to which the numeric string is appended.
		* @param n integer value.
		* @param p memory pool used during formatting.
		*/
		virtual void numberFormat(LogString& s,
			int n,
			LOG4CXX_NS::helpers::Pool& p) const;

		/**
		 * Gets maximum cache validity for the specified SimpleDateTime
		 *    conversion pattern.
		 *  @param pattern conversion pattern, may not be null.
		 *  @returns Duration in microseconds from an integral second
		 *      that the cache will return consistent results.
		 */
		static int getMaximumCacheValidity(const LogString& pattern);

	private:
		CachedDateFormat(const CachedDateFormat&);
		CachedDateFormat& operator=(const CachedDateFormat&);

		/**
		* Tests if two string regions are equal.
		* @param target target string.
		* @param toffset character position in target to start comparison.
		* @param other other string.
		* @param ooffset character position in other to start comparison.
		* @param len length of region.
		* @return true if regions are equal.
		*/
		static bool regionMatches(
			const LogString& target,
			size_t toffset,
			const LogString& other,
			size_t ooffset,
			size_t len);

};



}  // namespace helpers
} // namespace log4cxx

#endif // _LOG4CXX_HELPERS_SIMPLE_DATE_FORMAT_H
