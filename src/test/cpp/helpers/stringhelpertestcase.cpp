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
#include "../insertwide.h"
#include "../logunit.h"


using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   Unit test for StringHelper.


*/
LOGUNIT_CLASS(StringHelperTestCase)
{
	LOGUNIT_TEST_SUITE( StringHelperTestCase );
	LOGUNIT_TEST( testStartsWith1 );
	LOGUNIT_TEST( testStartsWith2 );
	LOGUNIT_TEST( testStartsWith3 );
	LOGUNIT_TEST( testStartsWith4 );
	LOGUNIT_TEST( testStartsWith5 );
	LOGUNIT_TEST( testEndsWith1 );
	LOGUNIT_TEST( testEndsWith2 );
	LOGUNIT_TEST( testEndsWith3 );
	LOGUNIT_TEST( testEndsWith4 );
	LOGUNIT_TEST( testEndsWith5 );
	LOGUNIT_TEST( testFormatEmptyPattern );
	LOGUNIT_TEST( testFormatMissingArgument );
	LOGUNIT_TEST( testToLowerCaseAscii );
	LOGUNIT_TEST( testToLowerCaseNonAsciiPassesThrough );
	LOGUNIT_TEST_SUITE_END();


public:

	/**
	 * Check that startsWith("foobar", "foo") returns true.
	 */
	void testStartsWith1()
	{
		LOGUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("foo")));
	}

	/**
	 * Check that startsWith("bar", "foobar") returns false.
	 */
	void testStartsWith2()
	{
		LOGUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(LOG4CXX_STR("foo"), LOG4CXX_STR("foobar")));
	}

	/**
	 * Check that startsWith("foobar", "foobar") returns true.
	 */
	void testStartsWith3()
	{
		LOGUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("foobar")));
	}

	/**
	 * Check that startsWith("foobar", "") returns true.
	 */
	void testStartsWith4()
	{
		LOGUNIT_ASSERT_EQUAL(true, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("")));
	}

	/**
	 * Check that startsWith("foobar", "abc") returns false.
	 */
	void testStartsWith5()
	{
		LOGUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("abc")));
	}



	/**
	 * Check that endsWith("foobar", "bar") returns true.
	 */
	void testEndsWith1()
	{
		LOGUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("bar")));
	}

	/**
	 * Check that endsWith("bar", "foobar") returns false.
	 */
	void testEndsWith2()
	{
		LOGUNIT_ASSERT_EQUAL(false, StringHelper::endsWith(LOG4CXX_STR("bar"), LOG4CXX_STR("foobar")));
	}

	/**
	 * Check that endsWith("foobar", "foobar") returns true.
	 */
	void testEndsWith3()
	{
		LOGUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("foobar")));
	}

	/**
	 * Check that endsWith("foobar", "") returns true.
	 */
	void testEndsWith4()
	{
		LOGUNIT_ASSERT_EQUAL(true, StringHelper::endsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("")));
	}

	/**
	 * Check that endsWith("foobar", "abc") returns false.
	 */
	void testEndsWith5()
	{
		LOGUNIT_ASSERT_EQUAL(false, StringHelper::startsWith(LOG4CXX_STR("foobar"), LOG4CXX_STR("abc")));
	}

	void testFormatEmptyPattern()
	{
		std::vector<LogString> params;
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR(""), StringHelper::format(LOG4CXX_STR(""), params));
	}

	void testFormatMissingArgument()
	{
		std::vector<LogString> params(1);
		params[0] = LOG4CXX_STR("first");
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("first {1}"), StringHelper::format(LOG4CXX_STR("{0} {1}"), params));
	}

	void testToLowerCaseAscii()
	{
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("hello world"),
			StringHelper::toLowerCase(LOG4CXX_STR("Hello World")));
	}

	// Regression: passing a non-ASCII byte (negative when char is signed, or > 0xFF
	// for wchar_t/UniChar) to ::tolower(int) is undefined behaviour. The prior
	// implementation also varied with the active C locale, producing different
	// output on different machines for the same configuration file. Verify the
	// non-ASCII bytes pass through unchanged regardless of locale.
	void testToLowerCaseNonAsciiPassesThrough()
	{
		LogString input;
		input.push_back(static_cast<logchar>('A'));
		input.push_back(static_cast<logchar>(0xC9));   // uppercase 'É' in Latin-1 / Windows-1252
		input.push_back(static_cast<logchar>(0xE9));   // lowercase 'é' in Latin-1 / Windows-1252
		input.push_back(static_cast<logchar>('Z'));
		LogString expected;
		expected.push_back(static_cast<logchar>('a'));
		expected.push_back(static_cast<logchar>(0xC9));
		expected.push_back(static_cast<logchar>(0xE9));
		expected.push_back(static_cast<logchar>('z'));
		LOGUNIT_ASSERT_EQUAL(expected, StringHelper::toLowerCase(input));
	}


};


LOGUNIT_TEST_SUITE_REGISTRATION(StringHelperTestCase);
