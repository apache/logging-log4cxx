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

#define __STDC_CONSTANT_MACROS
#include <log4cxx/helpers/datetimedateformat.h>
#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/helpers/pool.h>
#include <locale>
#include "../insertwide.h"
#include <apr.h>
#include <apr_time.h>
#include "localechanger.h"
#include <sstream>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace std;

#if defined(_WIN32)
#define LOCALE_US "English_us"
#define LOCALE_FR "French_france"
#else
#define LOCALE_US "en_US"
#define LOCALE_FR "fr_FR"
#endif


/**
   Unit test {@link DateTimeDateFormat}.
   @author Curt Arnold
   @since 0.9.8
*/
class DateTimeDateFormatTestCase : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE( DateTimeDateFormatTestCase );
  CPPUNIT_TEST( test1 );
  CPPUNIT_TEST( test2 );
  CPPUNIT_TEST( test3 );
  CPPUNIT_TEST( test4 );
  CPPUNIT_TEST( test5 );
  CPPUNIT_TEST( test6 );
//  Unexpectedly failing on Gump machine, 
//   LocaleChanger not catching exception on locale creation failure
//   despite catch blocks.
//  CPPUNIT_TEST( test7 );
  CPPUNIT_TEST( test8 );
  CPPUNIT_TEST_SUITE_END();



private:

#define MICROSECONDS_PER_DAY APR_INT64_C(86400000000)


  /**
   Asserts that formatting the provided date results in the expected string.

  @param date Date date
   @param timeZone TimeZone timezone for conversion
   @param expected String expected string
  */
  void assertFormattedTime( apr_time_t date, const std::locale& locale,
       const TimeZonePtr& timeZone, const LogString& expected )
       {
         DateTimeDateFormat formatter(locale);
         formatter.setTimeZone(timeZone);
         LogString actual;
         Pool p;
         formatter.format(actual, date, p);
         CPPUNIT_ASSERT_EQUAL( expected, actual );
  }

  /** Convert 02 Jan 2004 00:00:00 GMT for GMT. */
  void test1()
  {
    //
    //   02 Jan 2004 00:00 GMT
    //
    apr_time_t jan2 = MICROSECONDS_PER_DAY * 12419;
    std::locale localeUS(LOCALE_US);
    assertFormattedTime( jan2, localeUS, TimeZone::getGMT(), LOG4CXX_STR("02 Jan 2004 00:00:00,000"));
  }

  /** Convert 03 Jan 2004 00:00:00 GMT for America/Chicago. */
  void test2()
  {
    //
    //   03 Jan 2004 00:00 GMT
    apr_time_t jan3 = MICROSECONDS_PER_DAY * 12420;
    std::locale localeUS(LOCALE_US);
    assertFormattedTime( jan3, localeUS,
             TimeZone::getTimeZone(LOG4CXX_STR("GMT-6")),
             LOG4CXX_STR("02 Jan 2004 18:00:00,000"));
  }


  /** Convert 30 Jun 2004 00:00:00 GMT for GMT. */
  void test3()
  {
    apr_time_t jun30 = MICROSECONDS_PER_DAY * 12599;
    std::locale localeUS(LOCALE_US);
    assertFormattedTime( jun30, localeUS, TimeZone::getGMT(),
           LOG4CXX_STR("30 Jun 2004 00:00:00,000"));
  }

  /** Convert 29 Jun 2004 00:00:00 GMT for Chicago, daylight savings in effect. */
  void test4()
  {
    apr_time_t jul1 = MICROSECONDS_PER_DAY * 12600;
    std::locale localeUS(LOCALE_US);
    assertFormattedTime( jul1, localeUS,
           TimeZone::getTimeZone(LOG4CXX_STR("GMT-5")),
           LOG4CXX_STR("30 Jun 2004 19:00:00,000"));
  }

  /** Test multiple calls in close intervals. */
  void test5()
  {
    //   subsequent calls within one minute
    //     are optimized to reuse previous formatted value
    //     make a couple of nearly spaced calls
    apr_time_t ticks = MICROSECONDS_PER_DAY * 12601;
    std::locale localeUS(LOCALE_US);
    assertFormattedTime( ticks, localeUS, TimeZone::getGMT(),
           LOG4CXX_STR("02 Jul 2004 00:00:00,000"));
    assertFormattedTime( ticks + 8000, localeUS, TimeZone::getGMT(),
           LOG4CXX_STR("02 Jul 2004 00:00:00,008"));
    assertFormattedTime( ticks + 17000, localeUS, TimeZone::getGMT(),
           LOG4CXX_STR("02 Jul 2004 00:00:00,017"));
    assertFormattedTime( ticks + 237000, localeUS, TimeZone::getGMT(),
           LOG4CXX_STR("02 Jul 2004 00:00:00,237"));
    assertFormattedTime( ticks + 1415000, localeUS, TimeZone::getGMT(),
           LOG4CXX_STR("02 Jul 2004 00:00:01,415"));
  }

  /** Check that caching does not disregard timezone. This test would fail for revision 1.4 of DateTimeDateFormat.java. */
  void test6()
  {
    apr_time_t jul3 = MICROSECONDS_PER_DAY * 12602;
    std::locale localeUS(LOCALE_US);
    assertFormattedTime( jul3, localeUS, TimeZone::getGMT(),
        LOG4CXX_STR("03 Jul 2004 00:00:00,000"));
    assertFormattedTime( jul3, localeUS,
          TimeZone::getTimeZone(LOG4CXX_STR("GMT-5")),
          LOG4CXX_STR("02 Jul 2004 19:00:00,000"));
    assertFormattedTime( jul3, localeUS, TimeZone::getGMT(),
          LOG4CXX_STR("03 Jul 2004 00:00:00,000"));
  }

  LogString formatDate(const std::locale& locale, const tm& date, const LogString& fmt) {
        //
        //  output the using STL
        //
        std::basic_ostringstream<logchar> buffer;
#if defined(_USEFAC)
         _USEFAC(locale, std::time_put<logchar>)
             .put(buffer, buffer, &date, fmt.c_str(), fmt.c_str() + fmt.length());
#else
         std::use_facet<std::time_put<logchar> >(locale)
             .put(buffer, buffer, buffer.fill(), &date, fmt.c_str(), fmt.c_str() + fmt.length());
#endif
        return buffer.str();
  }

  /** Check that format is locale sensitive. */
  void test7()
  {
    apr_time_t avr11 = MICROSECONDS_PER_DAY * 12519;
    LocaleChanger localeChange(LOCALE_FR);
    if (localeChange.isEffective()) {
        LogString formatted;
        Pool p;
        SimpleDateFormat formatter(LOG4CXX_STR("MMM"));
        formatter.format(formatted, avr11, p);
        
        std::locale localeFR(LOCALE_FR);
        struct tm avr11tm = { 0, 0, 0, 11, 03, 104 };
        LogString expected(formatDate(localeFR, avr11tm, LOG4CXX_STR("%b")));
        
        CPPUNIT_ASSERT_EQUAL(expected, formatted);
    }
  }

  /** Check that format is locale sensitive. */
  void test8()
  {
    apr_time_t apr11 = MICROSECONDS_PER_DAY * 12519;
    LocaleChanger localeChange(LOCALE_US);
    if (localeChange.isEffective()) {
        LogString formatted;
        Pool p;
        SimpleDateFormat formatter(LOG4CXX_STR("MMM"));
        formatter.setTimeZone(TimeZone::getGMT());
        formatter.format(formatted, apr11, p);

        std::locale localeUS(LOCALE_US);
        struct tm apr11tm = { 0, 0, 0, 11, 03, 104 };
        LogString expected(formatDate(localeUS, apr11tm, LOG4CXX_STR("%b")));

        CPPUNIT_ASSERT_EQUAL(expected, formatted);
    }
  }


};

CPPUNIT_TEST_SUITE_REGISTRATION(DateTimeDateFormatTestCase);

