/*
 * Copyright 2005 The Apache Software Foundation.
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
#if LOG4CXX_HAS_WCHAR_T
     CPPUNIT_TEST( testWideStartsWith1 );
     CPPUNIT_TEST( testWideStartsWith2 );
     CPPUNIT_TEST( testWideStartsWith3 );
     CPPUNIT_TEST( testWideStartsWith4 );
     CPPUNIT_TEST( testWideStartsWith5 );
#endif
     CPPUNIT_TEST( testStartsWith1 );
     CPPUNIT_TEST( testStartsWith2 );
     CPPUNIT_TEST( testStartsWith3 );
     CPPUNIT_TEST( testStartsWith4 );
     CPPUNIT_TEST( testStartsWith5 );
#if LOG4CXX_HAS_WCHAR_T
     CPPUNIT_TEST( testWideEndsWith1 );
     CPPUNIT_TEST( testWideEndsWith2 );
     CPPUNIT_TEST( testWideEndsWith3 );
     CPPUNIT_TEST( testWideEndsWith4 );
     CPPUNIT_TEST( testWideEndsWith5 );
#endif
     CPPUNIT_TEST( testEndsWith1 );
     CPPUNIT_TEST( testEndsWith2 );
     CPPUNIT_TEST( testEndsWith3 );
     CPPUNIT_TEST( testEndsWith4 );
     CPPUNIT_TEST( testEndsWith5 );
     CPPUNIT_TEST_SUITE_END();


public:
#if LOG4CXX_HAS_WCHAR_T
  /**
   * Check that startsWith("foobar", "foo") returns true.
   */
  void testWideStartsWith1() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(L"foobar", L"foo"));
  }

  /**
   * Check that startsWith("foo", "foobar") returns false.
   */
  void testWideStartsWith2() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(L"foo", L"foobar"));
  }

  /**
   * Check that startsWith("foobar", "foobar") returns true.
   */
  void testWideStartsWith3() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(L"foobar", L"foobar"));
  }

  /**
   * Check that startsWith("foobar", "") returns true.
   */
  void testWideStartsWith4() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(L"foobar", L""));
  }

  /**
   * Check that startsWith("foobar", "abc") returns false.
   */
  void testWideStartsWith5() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(L"foobar", L"abc"));
  }
#endif

  /**
   * Check that startsWith("foobar", "foo") returns true.
   */
  void testStartsWith1() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith("foobar", "foo"));
  }

  /**
   * Check that startsWith("bar", "foobar") returns false.
   */
  void testStartsWith2() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith("foo", "foobar"));
  }

  /**
   * Check that startsWith("foobar", "foobar") returns true.
   */
  void testStartsWith3() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith("foobar", "foobar"));
  }

  /**
   * Check that startsWith("foobar", "") returns true.
   */
  void testStartsWith4() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::startsWith("foobar", ""));
  }

  /**
   * Check that startsWith("foobar", "abc") returns false.
   */
  void testStartsWith5() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith("foobar", "abc"));
  }


#if LOG4CXX_HAS_WCHAR_T
  /**
   * Check that endsWith("foobar", "bar") returns true.
   */
  void testWideEndsWith1() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(L"foobar", L"bar"));
  }

  /**
   * Check that endsWith("bar", "foobar") returns false.
   */
  void testWideEndsWith2() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::endsWith(L"bar", L"foobar"));
  }

  /**
   * Check that endsWith("foobar", "foobar") returns true.
   */
  void testWideEndsWith3() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(L"foobar", L"foobar"));
  }

  /**
   * Check that endsWith("foobar", "") returns true.
   */
  void testWideEndsWith4() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(L"foobar", L""));
  }

  /**
   * Check that endsWith("foobar", "abc") returns false.
   */
  void testWideEndsWith5() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(L"foobar", L"abc"));
  }
#endif

  /**
   * Check that endsWith("foobar", "bar") returns true.
   */
  void testEndsWith1() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith("foobar", "bar"));
  }

  /**
   * Check that endsWith("bar", "foobar") returns false.
   */
  void testEndsWith2() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::endsWith("bar", "foobar"));
  }

  /**
   * Check that endsWith("foobar", "foobar") returns true.
   */
  void testEndsWith3() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith("foobar", "foobar"));
  }

  /**
   * Check that endsWith("foobar", "") returns true.
   */
  void testEndsWith4() {
    CPPUNIT_ASSERT_EQUAL(true, StringHelper::endsWith("foobar", ""));
  }

  /**
   * Check that endsWith("foobar", "abc") returns false.
   */
  void testEndsWith5() {
    CPPUNIT_ASSERT_EQUAL(false, StringHelper::startsWith("foobar", "abc"));
  }


};


CPPUNIT_TEST_SUITE_REGISTRATION(StringHelperTestCase);
