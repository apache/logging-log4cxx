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

#include <log4cxx/helpers/datetimedateformat.h>
#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/helpers/pool.h>
#include <locale>
#include "../insertwide.h"
#include <apr.h>
#include <apr_time.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

#if defined(_WIN32)
#define LOCALE_US "English_us"
#define LOCALE_FR "French_france"
#else
#define LOCALE_US "en_US"
#define LOCALE_FR "fr_FR"
#endif

//Define INT64_C for compilers that don't have it
#if (!defined(INT64_C))
#define INT64_C(value)  value ## LL
#endif


class LocaleChanger {
public:
  LocaleChanger(const char* locale) {
    try {
        std::locale newLocale(locale);
        initial = std::locale::global(newLocale);
        effective = true;
    } catch(std::exception&) {
    }
  }

  ~LocaleChanger() {
      if (effective) {
        std::locale::global(initial);
      }
  }
  inline bool isEffective() { return effective; }

private:
  LocaleChanger(LocaleChanger&);
  LocaleChanger& operator=(LocaleChanger&);
  std::locale initial;
  bool effective;
};


/**
   Unit test {@link DateTimeDateFormat}.
   @author Curt Arnold
   @since 1.3.0
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
  CPPUNIT_TEST( test7 );
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


  /** Check that format is locale sensitive. */
  void test7()
  {
    apr_time_t mars11 = MICROSECONDS_PER_DAY * 12519;
    LocaleChanger localeChange(LOCALE_FR);
    if (localeChange.isEffective()) {
        LogString formatted;
        Pool p;
        DateTimeDateFormat formatter;
        formatter.setTimeZone(TimeZone::getGMT());
        formatter.format(formatted, mars11, p);
        CPPUNIT_ASSERT_EQUAL((LogString)  LOG4CXX_STR("11 avr. 2004 00:00:00,000"), formatted );
    }
  }

  /** Check that format is locale sensitive. */
  void test8()
  {
    apr_time_t march12 = MICROSECONDS_PER_DAY * 12519;
    LocaleChanger localeChange(LOCALE_US);
    if (localeChange.isEffective()) {
        LogString formatted;
        Pool p;
        DateTimeDateFormat formatter;
        formatter.setTimeZone(TimeZone::getGMT());
        formatter.format(formatted, march12, p);
        CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("11 Apr 2004 00:00:00,000"), formatted );
    }
  }


};

CPPUNIT_TEST_SUITE_REGISTRATION(DateTimeDateFormatTestCase);

