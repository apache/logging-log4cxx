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

#include <log4cxx/helpers/iso8601dateformat.h>
#include <cppunit/extensions/HelperMacros.h>
#include <apr-1/apr_pools.h>
#include <locale>

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   Unit test {@link ISO8601DateFormat}.
   @author Curt Arnold
   @since 1.3.0 */
   class ISO8601DateFormatTestCase : public CppUnit::TestFixture
   {
     CPPUNIT_TEST_SUITE( ISO8601DateFormatTestCase );
     CPPUNIT_TEST( test1 );
     CPPUNIT_TEST( test2 );
     CPPUNIT_TEST( test3 );
     CPPUNIT_TEST( test4 );
     CPPUNIT_TEST( test5 );
     CPPUNIT_TEST( test6 );
     CPPUNIT_TEST( test7 );
     CPPUNIT_TEST_SUITE_END();

  /**
   * Asserts that formatting the provided date results
   * in the expected string.
   *
   * @param date Date date
   * @param timeZone TimeZone timezone for conversion
   * @param expected String expected string
   */
  void assertFormattedTime(apr_time_t date,
                           const TimeZonePtr& timeZone,
                           const std::string& expected) {
    ISO8601DateFormat formatter;
    formatter.setTimeZone(timeZone);
    std::string actual;
    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
    formatter.format(actual, date, p);
    apr_pool_destroy(p);
    CPPUNIT_ASSERT_EQUAL(expected, actual);
  }

#define MICROSECONDS_PER_DAY APR_INT64_C(86400000000)

public:
  /**
   * Convert 02 Jan 2004 00:00:00 GMT for GMT.
   */
  void test1() {
    apr_time_t jan2 = MICROSECONDS_PER_DAY * 12419;
    assertFormattedTime(jan2, TimeZone::getGMT(), "2004-01-02 00:00:00,000");
  }

  /**
   * Convert 03 Jan 2004 00:00:00 GMT for America/Chicago.
   */
  void test2() {
    //
    //   03 Jan 2004 00:00 GMT
    //       (asking for the same time at a different timezone
    //          will ignore the change of timezone)
    apr_time_t jan3 = MICROSECONDS_PER_DAY * 12420;
    assertFormattedTime(jan3, TimeZone::getTimeZone("GMT-6"), "2004-01-02 18:00:00,000");
  }


  /**
   * Convert 30 Jun 2004 00:00:00 GMT for GMT.
   */
  void test3() {
    apr_time_t jun30 = MICROSECONDS_PER_DAY * 12599;
    assertFormattedTime(jun30, TimeZone::getGMT(), "2004-06-30 00:00:00,000");
  }

  /**
   * Convert 1 Jul 2004 00:00:00 GMT for Chicago, daylight savings in effect.
   */
  void test4() {
    apr_time_t jul1 = MICROSECONDS_PER_DAY * 12600;
    assertFormattedTime(jul1, TimeZone::getTimeZone("GMT-5"), "2004-06-30 19:00:00,000");
  }

  /**
   * Test multiple calls in close intervals.
   */
  void test5() {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    apr_time_t ticks =  MICROSECONDS_PER_DAY * 12601;
    assertFormattedTime(ticks, TimeZone::getGMT(), "2004-07-02 00:00:00,000");
    assertFormattedTime(ticks + 8000, TimeZone::getGMT(), "2004-07-02 00:00:00,008");
    assertFormattedTime(ticks + 17000, TimeZone::getGMT(), "2004-07-02 00:00:00,017");
    assertFormattedTime(ticks + 237000, TimeZone::getGMT(), "2004-07-02 00:00:00,237");
    assertFormattedTime(ticks + 1415000, TimeZone::getGMT(), "2004-07-02 00:00:01,415");
  }

  /**
   *  Check that caching does not disregard timezone.
   * This test would fail for revision 1.4 of DateTimeDateFormat.java.
   */
  void test6() {
    apr_time_t jul3 =  MICROSECONDS_PER_DAY * 12602;
    assertFormattedTime(jul3, TimeZone::getGMT(), "2004-07-03 00:00:00,000");
    assertFormattedTime(jul3, TimeZone::getTimeZone("GMT-5"), "2004-07-02 19:00:00,000");
    assertFormattedTime(jul3, TimeZone::getGMT(), "2004-07-03 00:00:00,000");
  }

  /**
   * Checks that numberFormat is implemented.
   */
  void test7() {
    std::string number;
    ISO8601DateFormat formatter;
    apr_pool_t* p;
    apr_pool_create(&p, NULL);
    formatter.numberFormat(number, 87, p);
    apr_pool_destroy(p);
    CPPUNIT_ASSERT_EQUAL((std::string) "87", number);
  }



};


CPPUNIT_TEST_SUITE_REGISTRATION(ISO8601DateFormatTestCase);
