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

#include <log4cxx/helpers/absolutetimedateformat.h>
#include <cppunit/extensions/HelperMacros.h>
#include <apr_pools.h>

using namespace log4cxx;
using namespace log4cxx::helpers;



/**
   Unit test {@link AbsoluteTimeDateFormat}.
   @author Curt Arnold
   @since 1.3.0 */
class AbsoluteTimeDateFormatTestCase : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(AbsoluteTimeDateFormatTestCase);
          CPPUNIT_TEST(test1);
          CPPUNIT_TEST(test2);
          CPPUNIT_TEST(test3);
          CPPUNIT_TEST(test4);
          CPPUNIT_TEST(test5);
          CPPUNIT_TEST(test6);
          CPPUNIT_TEST(test7);
          CPPUNIT_TEST(test8);
  CPPUNIT_TEST_SUITE_END();

  public:

  /**
   * Asserts that formatting the provided date results
   * in the expected string.
   *
   * @param date Date date
   * @param timeZone TimeZone timezone for conversion
   * @param expected String expected string
   */
  private:
  void assertFormattedTime(apr_time_t date,
                           const TimeZonePtr& timeZone,
                           const std::string& expected) {
    AbsoluteTimeDateFormat formatter;
    formatter.setTimeZone(timeZone);
    std::string actual;
    apr_pool_t* p;
    apr_pool_create(&p, NULL);
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
    //
    //   02 Jan 2004 00:00 GMT
    //
    apr_time_t jan2 = MICROSECONDS_PER_DAY * 12419;
    assertFormattedTime(jan2, TimeZone::getGMT(), "00:00:00,000");
  }

  /**
   * Convert 03 Jan 2004 00:00:00 GMT for America/Chicago.
   */
  void test2() {
    //
    //   03 Jan 2004 00:00 GMT
    //       (asking for the same time at a different timezone
    //          will ignore the change of timezone)
    apr_time_t jan2 = MICROSECONDS_PER_DAY * 12420;
    assertFormattedTime(jan2, TimeZone::getTimeZone("GMT-6"), "18:00:00,000");
  }

  /**
   * Convert 29 Jun 2004 00:00:00 GMT for GMT.
   */
  void test3() {
    apr_time_t jun29 = MICROSECONDS_PER_DAY * 12599;
    assertFormattedTime(jun29, TimeZone::getGMT(), "00:00:00,000");
  }

  /**
   * Convert 29 Jun 2004 00:00:00 GMT for Chicago, daylight savings in effect.
   */
  void test4() {
    apr_time_t jun30 = MICROSECONDS_PER_DAY * 12600;
    //
    //   log4cxx doesn't support non-fixed timezones at this time
    //      passing the fixed equivalent to Chicago's Daylight Savings Time
    //
    assertFormattedTime(jun30, TimeZone::getTimeZone("GMT-5"), "19:00:00,000");
  }

  /**
   * Test multiple calls in close intervals.
   */
  void test5() {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    apr_time_t ticks = MICROSECONDS_PER_DAY * 12601;
    assertFormattedTime(ticks, TimeZone::getGMT(), "00:00:00,000");
    assertFormattedTime(ticks + 8000, TimeZone::getGMT(), "00:00:00,008");
    assertFormattedTime(ticks + 17000, TimeZone::getGMT(), "00:00:00,017");
    assertFormattedTime(ticks + 237000, TimeZone::getGMT(), "00:00:00,237");
    assertFormattedTime(ticks + 1415000, TimeZone::getGMT(), "00:00:01,415");
  }

  /**
   *  Check that caching does not disregard timezone.
   * This test would fail for revision 1.4 of AbsoluteTimeDateFormat.java.
   */
  void test6() {
    apr_time_t jul2 = MICROSECONDS_PER_DAY * 12602;
    assertFormattedTime(jul2, TimeZone::getGMT(), "00:00:00,000");
    assertFormattedTime(jul2, TimeZone::getTimeZone("GMT-5"), "19:00:00,000");
  }

  /**
   * Test multiple calls in close intervals predating 1 Jan 1970.
   */
  void test7() {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    apr_time_t ticks = MICROSECONDS_PER_DAY * -7;
    assertFormattedTime(ticks, TimeZone::getGMT(), "00:00:00,000");
#if defined(_WIN32)
    //
    //   These tests fail on Unix due to bug in APR's explode_time
    //
//    assertFormattedTime(ticks + 8000, TimeZone::getGMT(), "00:00:00,008");
//    assertFormattedTime(ticks + 17000, TimeZone::getGMT(), "00:00:00,017");
//    assertFormattedTime(ticks + 237000, TimeZone::getGMT(), "00:00:00,237");
//    assertFormattedTime(ticks + 1415000, TimeZone::getGMT(), "00:00:01,415");
#endif
  }

  /**
   * Checks that numberFormat works as expected.
   */
  void test8() {
    std::string numb;
    apr_pool_t* p;
    apr_pool_create(&p, NULL);
    AbsoluteTimeDateFormat formatter;
    formatter.numberFormat(numb, 87, p);
    apr_pool_destroy(p);
    CPPUNIT_ASSERT_EQUAL((std::string) "87", numb);
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(AbsoluteTimeDateFormatTestCase);

