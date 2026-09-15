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

#define __STDC_CONSTANT_MACROS
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/simpledateformat.h>
#include "../logunit.h"
#include <log4cxx/helpers/pool.h>
#include "../insertwide.h"
#include <apr.h>
#include <apr_time.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>

#if LOG4CXX_HAS_STD_LOCALE
	#include <locale>
	#define MAKE_LOCALE(ptr, id)     \
		std::locale loco(id);        \
		std::locale* ptr = &loco;
#else
	#define MAKE_LOCALE(ptr, id)     \
		std::locale* ptr = NULL;
#endif

/**
 * Unit test for {@link SimpleDateFormat}.
 */
LOGUNIT_CLASS(SimpleDateFormatTestCase)
{
	LOGUNIT_TEST_SUITE( SimpleDateFormatTestCase );
	LOGUNIT_TEST( testNameFields );
	LOGUNIT_TEST( testExtremeTimesDoNotReadOutOfBounds );
	LOGUNIT_TEST_SUITE_END();

#define MICROSECONDS_PER_DAY APR_INT64_C(86400000000)

public:
	/**
	 * The day-name, month-name and AM/PM tokens index fixed-size name tables.
	 * Verify that ordinary formatting of those fields is unchanged after the
	 * bounds-checking added to guard against out-of-range time fields.
	 */
	void testNameFields()
	{
		// 02 Jan 2004 00:00:00 GMT is a Friday.
		apr_time_t jan2_2004 = MICROSECONDS_PER_DAY * 12419;
		MAKE_LOCALE(localeUS, "C");

		{
			SimpleDateFormat fmt(LOG4CXX_STR("EEE"), localeUS);
			fmt.setTimeZone(TimeZone::getGMT());
			LogString actual;
			fmt.format(actual, jan2_2004);
			LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Fri")), actual);
		}
		{
			SimpleDateFormat fmt(LOG4CXX_STR("MMM"), localeUS);
			fmt.setTimeZone(TimeZone::getGMT());
			LogString actual;
			fmt.format(actual, jan2_2004);
			LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Jan")), actual);
		}
		{
			SimpleDateFormat fmt(LOG4CXX_STR("a"), localeUS);
			fmt.setTimeZone(TimeZone::getGMT());
			LogString actual;
			fmt.format(actual, jan2_2004);
			LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("AM")), actual);
		}
	}

	/**
	 * Extreme apr_time_t values can make APR's time-explosion arithmetic
	 * overflow and produce an out-of-range tm_wday / tm_mon / tm_hour. The
	 * day-name, month-name and AM/PM tokens previously indexed their fixed-size
	 * name tables with those unchecked values, which is an out-of-bounds
	 * std::vector read (a heap-buffer-overflow flagged by AddressSanitizer).
	 *
	 * This exercises the affected tokens with such values and asserts the format
	 * completes with a bounded result rather than reading out of bounds.
	 */
	void testExtremeTimesDoNotReadOutOfBounds()
	{
		MAKE_LOCALE(localeUS, "C");

		const apr_time_t times[] =
		{ (apr_time_t) APR_INT64_MAX
		, (apr_time_t) APR_INT64_MIN
		, (apr_time_t)(APR_INT64_MAX - 1)
		, (apr_time_t) APR_INT64_C(-19503744426494601)
		, (apr_time_t) APR_INT64_C(9000000000000000000)
		, (apr_time_t) APR_INT64_C(-9000000000000000000)
		};

		const LogString patterns[] =
		{ LOG4CXX_STR("EEE")
		, LOG4CXX_STR("EEEE")
		, LOG4CXX_STR("MMM")
		, LOG4CXX_STR("MMMM")
		, LOG4CXX_STR("a")
		, LOG4CXX_STR("EEEE, d MMMM yyyy a")
		};

		for (auto t : times)
		{
			for (auto p : patterns)
			{
				SimpleDateFormat fmt(LogString(p), localeUS);
				LogString actual;
				fmt.format(actual, t);          // must not read out of bounds
				LOGUNIT_ASSERT(actual.length() < 1000);
			}
		}
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(SimpleDateFormatTestCase);
