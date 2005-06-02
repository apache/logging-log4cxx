/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

#include <log4cxx/helpers/timezone.h>
#include <cppunit/extensions/HelperMacros.h>
#include "../insertwide.h"
#include <apr_time.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

//Define INT64_C for compilers that don't have it
#if (!defined(INT64_C))
#define INT64_C(value)  value ## LL
#endif


/**
   Unit test {@link TimeZone}.
   @author Curt Arnold
   @since 0.98 */
class TimeZoneTestCase : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(TimeZoneTestCase);
          CPPUNIT_TEST(test1);
          CPPUNIT_TEST(test2);
#if !defined(__BORLANDC__)
          CPPUNIT_TEST(test3);
#endif
          CPPUNIT_TEST(test4);
          CPPUNIT_TEST(test5);
          CPPUNIT_TEST(test6);
  CPPUNIT_TEST_SUITE_END();

#define MICROSECONDS_PER_DAY APR_INT64_C(86400000000)


  public:
  /**
   * Checks the GMT timezone
   */
  void test1() {
    TimeZonePtr tz(TimeZone::getGMT());
    CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("GMT"), tz->getID());
  }

  /**
   * Get "GMT-6" time zone
   */
  void test2() {
    TimeZonePtr tz(TimeZone::getTimeZone(LOG4CXX_STR("GMT-6")));
    CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("GMT-06:00"), tz->getID());

    apr_time_t jan2 = MICROSECONDS_PER_DAY * 12420;
    apr_time_exp_t exploded;
    tz->explode(&exploded, jan2);
    CPPUNIT_ASSERT_EQUAL(-6 * 3600, exploded.tm_gmtoff);
    CPPUNIT_ASSERT_EQUAL(18, exploded.tm_hour);
  }

  /**
   * Get the default timezone name
   */
  void test3() {
    TimeZonePtr tz(TimeZone::getDefault());
    LogString tzName(tz->getID());
    CPPUNIT_ASSERT(tzName.length() > 0);
  }


/**
 * Get "GMT+0010" time zone
 */
void test4() {
  TimeZonePtr tz(TimeZone::getTimeZone(LOG4CXX_STR("GMT+0010")));
  CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("GMT+00:10"), tz->getID());

  apr_time_t jan2 = MICROSECONDS_PER_DAY * 12420;
  apr_time_exp_t exploded;
  tz->explode(&exploded, jan2);
  CPPUNIT_ASSERT_EQUAL(600, exploded.tm_gmtoff);
  CPPUNIT_ASSERT_EQUAL(0, exploded.tm_hour);
  CPPUNIT_ASSERT_EQUAL(10, exploded.tm_min);
}


/**
 * Get "GMT+6" time zone
 */
void test5() {
  TimeZonePtr tz(TimeZone::getTimeZone(LOG4CXX_STR("GMT+6")));
  CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("GMT+06:00"), tz->getID());

  apr_time_t jan2 = MICROSECONDS_PER_DAY * 12420;
  apr_time_exp_t exploded;
  tz->explode(&exploded, jan2);
  CPPUNIT_ASSERT_EQUAL(6 * 3600, exploded.tm_gmtoff);
  CPPUNIT_ASSERT_EQUAL(6, exploded.tm_hour);
}

/**
 * Checks the GMT timezone
 */
void test6() {
  TimeZonePtr tz(TimeZone::getTimeZone(LOG4CXX_STR("GMT")));
  CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("GMT"), tz->getID());
}


};

CPPUNIT_TEST_SUITE_REGISTRATION(TimeZoneTestCase);

