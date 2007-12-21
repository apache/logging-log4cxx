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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/stringhelper.h>
#include <cppunit/extensions/HelperMacros.h>
#include "../insertwide.h"


using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   Unit test for StringHelper.
   @author Curt Arnold
   @since 0.9.8
*/
class StringHelperTestCase : public CppUnit::TestFixture
   {
     CPPUNIT_TEST_SUITE( StringHelperTestCase );
     CPPUNIT_TEST( testStartsWith1 );
     CPPUNIT_TEST( testStartsWith2 );
     CPPUNIT_TEST( testStartsWith3 );
     CPPUNIT_TEST( testStartsWith4 );
     CPPUNIT_TEST( testStartsWith5 );
     CPPUNIT_TEST( testEndsWith1 );
     CPPUNIT_TEST( testEndsWith2 );
     CPPUNIT_TEST( testEndsWith3 );
     CPPUNIT_TEST( testEndsWith4 );
     CPPUNIT_TEST( testEndsWith5 );
     CPPUNIT_TEST_SUITE_END();


public:

  /**
   * Check that startsWith("foobar", "foo") returns true.
   */
  void testStartsWith1() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("foo")));
  }

  /**
   * Check that startsWith("bar", "foobar") returns false.
   */
  void testStartsWith2() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(LOG4CXX_STR("foo"), LOG4CXX_STR("foobar")));
  }

  /**
   * Check that startsWith("foobar", "foobar") returns true.
   */
  void testStartsWith3() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("foobar")));
  }

  /**
   * Check that startsWith("foobar", "") returns true.
   */
  void testStartsWith4() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("")));
  }

  /**
   * Check that startsWith("foobar", "abc") returns false.
   */
  void testStartsWith5() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("abc")));
  }



  /**
   * Check that endsWith("foobar", "bar") returns true.
   */
  void testEndsWith1() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("bar")));
  }

  /**
   * Check that endsWith("bar", "foobar") returns false.
   */
  void testEndsWith2() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::endsWith(LOG4CXX_STR("bar"), LOG4CXX_STR("foobar")));
  }

  /**
   * Check that endsWith("foobar", "foobar") returns true.
   */
  void testEndsWith3() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("foobar")));
  }

  /**
   * Check that endsWith("foobar", "") returns true.
   */
  void testEndsWith4() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("")));
  }

  /**
   * Check that endsWith("foobar", "abc") returns false.
   */
  void testEndsWith5() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("abc")));
  }


};


CPPUNIT_TEST_SUITE_REGISTRATION(StringHelperTestCase);
