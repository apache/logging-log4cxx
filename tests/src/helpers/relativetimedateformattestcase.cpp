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


#include <log4cxx/helpers/relativetimedateformat.h>
#include <log4cxx/spi/loggingevent.h>
#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/helpers/pool.h>
#include <apr_strings.h>
#include <log4cxx/helpers/stringhelper.h>
#include "../insertwide.h"
#include <apr_time.h>

//Define INT64_C for compilers that don't have it
#if (!defined(INT64_C))
#define INT64_C(value)  value ## LL
#endif


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;


/**
   Unit test {@link RelativeTimeDateFormat} class.
   @author Curt Arnold
   @since 1.3.0 */
class RelativeTimeDateFormatTestCase  : public CppUnit::TestFixture {
     CPPUNIT_TEST_SUITE(RelativeTimeDateFormatTestCase);
             CPPUNIT_TEST(test1);
             CPPUNIT_TEST(test2);
             CPPUNIT_TEST(test3);
     CPPUNIT_TEST_SUITE_END();

#define MICROSECONDS_PER_DAY APR_INT64_C(86400000000)

  public:

  /**
  *   Convert 2 Jan 2004
  */
  void test1() {
    apr_time_t jan2 = MICROSECONDS_PER_DAY * 12419;
    apr_time_t preStartTime = LoggingEvent::getStartTime();

    RelativeTimeDateFormat formatter;

    Pool p;

    LogString actual;

    formatter.format(actual, jan2, p);

    apr_time_t elapsed = log4cxx::helpers::StringHelper::toInt64(actual);


    CPPUNIT_ASSERT(preStartTime + elapsed*1000 > jan2 - 2000);
    CPPUNIT_ASSERT(preStartTime + elapsed*1000 < jan2 + 2000);
  }


    /**
     * Checks that numberFormat works as expected.
     */
    void test2() {
      LogString numb;
      Pool p;
      RelativeTimeDateFormat formatter;
      formatter.numberFormat(numb, 87, p);
      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("87"), numb);
    }


  /**
   * Checks that setting timezone doesn't throw an exception.
   */
  void test3() {
    RelativeTimeDateFormat formatter;
    formatter.setTimeZone(TimeZone::getGMT());
  }

};

CPPUNIT_TEST_SUITE_REGISTRATION(RelativeTimeDateFormatTestCase);

