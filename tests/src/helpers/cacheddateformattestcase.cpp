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

#include <log4cxx/helpers/cacheddateformat.h>
#include <log4cxx/helpers/absolutetimedateformat.h>
#include <log4cxx/helpers/relativetimedateformat.h>
#include <cppunit/extensions/HelperMacros.h>
#include <apr-1/apr_pools.h>
#include <locale>

using namespace log4cxx;
using namespace log4cxx::helpers;


#if defined(_WIN32)
#define LOCALE_US "us"
#define LOCALE_JP "jpn"
#else
#define LOCALE_US "en_US"
#define LOCALE_JP "jp_JP"
#endif

/**
   Unit test {@link CachedDateFormat}.
   @author Curt Arnold
   @since 1.3.0 */
   class CachedDateFormatTestCase : public CppUnit::TestFixture
   {
     CPPUNIT_TEST_SUITE( CachedDateFormatTestCase );
     CPPUNIT_TEST( test1 );
     CPPUNIT_TEST( test2 );
     CPPUNIT_TEST( test3 );
     CPPUNIT_TEST( test4 );
#if !defined(_WIN32)
     CPPUNIT_TEST( test5 );
#endif
     CPPUNIT_TEST( test6 );
     CPPUNIT_TEST( test7 );
     CPPUNIT_TEST( test8 );
     CPPUNIT_TEST_SUITE_END();


#define MICROSECONDS_PER_DAY APR_INT64_C(86400000000)

   public:

  /**
   * Test multiple calls in close intervals.
   */
  void test1() {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    DateFormatPtr baseFormatter(new AbsoluteTimeDateFormat());
    CachedDateFormat gmtFormat(baseFormatter);
    gmtFormat.setTimeZone(TimeZone::getGMT());

    apr_time_t jul1 = MICROSECONDS_PER_DAY * 12601L;
    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

    std::string actual;

    gmtFormat.format(actual, jul1, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,000", actual);
    actual.erase(actual.begin(), actual.end());

    gmtFormat.format(actual, jul1 + 8000, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,008", actual);
    actual.erase(actual.begin(), actual.end());

    gmtFormat.format(actual, jul1 + 17000, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,017", actual);
    actual.erase(actual.begin(), actual.end());

    gmtFormat.format(actual, jul1 + 237000, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,237", actual);
    actual.erase(actual.begin(), actual.end());

    gmtFormat.format(actual, jul1 + 1415000, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:01,415", actual);
    actual.erase(actual.begin(), actual.end());

    apr_pool_destroy(p);
  }

  /**
   *  Check for interaction between caches.
   */

  void test2() {
      apr_time_t jul2 = MICROSECONDS_PER_DAY * 12602;
      DateFormatPtr baseFormatter(new AbsoluteTimeDateFormat());
      CachedDateFormat gmtFormat(baseFormatter);
      gmtFormat.setTimeZone(TimeZone::getGMT());

     DateFormatPtr chicagoBase(new AbsoluteTimeDateFormat());
     CachedDateFormat chicagoFormat(chicagoBase);
     chicagoFormat.setTimeZone(TimeZone::getTimeZone("GMT-5"));

     apr_pool_t* p;
     apr_status_t stat = apr_pool_create(&p, NULL);
     CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

     std::string actual;

     gmtFormat.format(actual, jul2, p);
     CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,000", actual);
     actual.erase(actual.begin(), actual.end());

      chicagoFormat.format(actual, jul2, p);
      CPPUNIT_ASSERT_EQUAL((std::string) "19:00:00,000", actual);
      actual.erase(actual.begin(), actual.end());

    gmtFormat.format(actual, jul2, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,000", actual);
    actual.erase(actual.begin(), actual.end());

    apr_pool_destroy(p);
  }

  /**
   * Test multiple calls in close intervals prior to 1 Jan 1970.
   */
  void test3() {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    DateFormatPtr baseFormatter(new AbsoluteTimeDateFormat());
    CachedDateFormat gmtFormat(baseFormatter);
    gmtFormat.setTimeZone(TimeZone::getGMT());

    apr_time_t ticks = MICROSECONDS_PER_DAY * -7;

    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

    std::string actual;


    gmtFormat.format(actual, ticks, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,000", actual);
    actual.erase(actual.begin(), actual.end());

#if defined(_WIN32)
   //
   //   APR's explode_time method does not properly calculate tm_usec
   //     prior to 1 Jan 1970 on Unix
   gmtFormat.format(actual, ticks + 8000, p);
   CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,008", actual);
   actual.erase(actual.begin(), actual.end());

   gmtFormat.format(actual, ticks + 17000, p);
   CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,017", actual);
   actual.erase(actual.begin(), actual.end());

    gmtFormat.format(actual, ticks + 237000, p);
    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:00,237", actual);
    actual.erase(actual.begin(), actual.end());

    gmtFormat.format(actual, ticks + 1415000, p);
//    Fails on both Linux and Win32
//    CPPUNIT_ASSERT_EQUAL((std::string) "00:00:01,415", actual);
#endif

    apr_pool_destroy(p);
  }

  void assertFormattedEquals(
      const DateFormatPtr& baseFormat,
      const CachedDateFormat& cachedFormat,
      apr_time_t date,
      apr_pool_t* p) {
        std::string expected;
        std::string actual;

        baseFormat->format(expected, date, p);
        cachedFormat.format(actual, date, p);

        CPPUNIT_ASSERT_EQUAL(expected, actual);
  }

  void test4() {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    std::locale localeEN(LOCALE_US);
    DateFormatPtr baseFormat(
         new SimpleDateFormat("EEE, MMM dd, HH:mm:ss.SSS Z", localeEN));
    CachedDateFormat cachedFormat(baseFormat);
    //
    //   use a date in 2000 to attempt to confuse the millisecond locator
    apr_time_t ticks = MICROSECONDS_PER_DAY * 11141;

    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

    assertFormattedEquals(baseFormat, cachedFormat, ticks, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 8000, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 17000, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 237000, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 1415000, p);

    apr_pool_destroy(p);
  }


  void test5() {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    std::locale localeJP(LOCALE_JP);
    DateFormatPtr baseFormat(
         new SimpleDateFormat("EEE, MMM dd, HH:mm:ss.SSS Z", localeJP));
    CachedDateFormat cachedFormat(baseFormat);
    //
    //   use a date in 2000 to attempt to confuse the millisecond locator
    apr_time_t ticks = MICROSECONDS_PER_DAY * 11141;

    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

    assertFormattedEquals(baseFormat, cachedFormat, ticks, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 8000, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 17000, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 237000, p);
    assertFormattedEquals(baseFormat, cachedFormat, ticks + 1415000, p);

    apr_pool_destroy(p);
  }

  /**
   * Checks that numberFormat works as expected.
   */
  void test6() {
    std::string numb;
    apr_pool_t* p;
    apr_pool_create(&p, NULL);
    AbsoluteTimeDateFormat formatter;
    formatter.numberFormat(numb, 87, p);
    apr_pool_destroy(p);
    CPPUNIT_ASSERT_EQUAL((std::string) "87", numb);
  }

  /**
   * Attempt to cache a RelativeTimeDateFormat which isn't compatible
   * with caching.  Should just delegate to the RelativeTimeDateFormat.
   */
   void test7() {
     //   subsequent calls within one minute
     //     are optimized to reuse previous formatted value
     //     make a couple of nearly spaced calls
     DateFormatPtr baseFormat(new RelativeTimeDateFormat());
     CachedDateFormat cachedFormat(baseFormat);
     //
     //   use a date in 2000 to attempt to confuse the millisecond locator
     apr_time_t ticks = MICROSECONDS_PER_DAY * 11141;

     apr_pool_t* p;
     apr_status_t stat = apr_pool_create(&p, NULL);
     CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

     assertFormattedEquals(baseFormat, cachedFormat, ticks, p);
     assertFormattedEquals(baseFormat, cachedFormat, ticks + 8000, p);
     assertFormattedEquals(baseFormat, cachedFormat, ticks + 17000, p);
     assertFormattedEquals(baseFormat, cachedFormat, ticks + 237000, p);
     assertFormattedEquals(baseFormat, cachedFormat, ticks + 1415000, p);

     apr_pool_destroy(p);
   }

  /**
   * Set time zone on cached and check that it is effective.
   */
  void test8() {
    DateFormatPtr baseFormat(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS"));
    CachedDateFormat cachedFormat(baseFormat);
    cachedFormat.setTimeZone(TimeZone::getTimeZone("GMT-6"));
    apr_time_t jul4 = MICROSECONDS_PER_DAY * 12603;

    apr_pool_t* p;
    apr_status_t stat = apr_pool_create(&p, NULL);
    CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

    std::string actual;
    cachedFormat.format(actual, jul4, p);

    CPPUNIT_ASSERT_EQUAL((std::string) "2004-07-03 18:00:00,000", actual);

    apr_pool_destroy(p);
  }

};


CPPUNIT_TEST_SUITE_REGISTRATION(CachedDateFormatTestCase);
