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
#include <stdexcept>


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
	LOGUNIT_TEST( testToIntAcceptsSign );
	LOGUNIT_TEST( testToIntParsesWholeString );
	LOGUNIT_TEST_EXCEPTION( testToIntRejectsEmptyString, std::invalid_argument );
	LOGUNIT_TEST_EXCEPTION( testToIntRejectsWhitespaceOnly, std::invalid_argument );
	LOGUNIT_TEST_EXCEPTION( testToIntRejectsEmbeddedWhitespace, std::invalid_argument );
	LOGUNIT_TEST_EXCEPTION( testToIntRejectsTrailingCharacters, std::invalid_argument );
	LOGUNIT_TEST_EXCEPTION( testToInt64RejectsTrailingCharacters, std::invalid_argument );
	LOGUNIT_TEST( testFormatEmptyPattern );
	LOGUNIT_TEST( testFormatMissingArgument );
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

	void testToIntAcceptsSign()
	{
		LOGUNIT_ASSERT_EQUAL(42, StringHelper::toInt(LOG4CXX_STR("+42")));
		LOGUNIT_ASSERT_EQUAL(-42, StringHelper::toInt(LOG4CXX_STR("-42")));
	}

	void testToIntParsesWholeString()
	{
		LOGUNIT_ASSERT_EQUAL(42, StringHelper::toInt(LOG4CXX_STR(" 42 \t")));
		LOGUNIT_ASSERT_EQUAL(int64_t(1234567890123LL), StringHelper::toInt64(LOG4CXX_STR("1234567890123")));
	}

	void testToIntRejectsEmptyString()
	{
		StringHelper::toInt(LOG4CXX_STR(""));
	}

	void testToIntRejectsWhitespaceOnly()
	{
		StringHelper::toInt(LOG4CXX_STR("   "));
	}

	void testToIntRejectsEmbeddedWhitespace()
	{
		StringHelper::toInt(LOG4CXX_STR("12 34"));
	}

	void testToIntRejectsTrailingCharacters()
	{
		StringHelper::toInt(LOG4CXX_STR("123abc"));
	}

	void testToInt64RejectsTrailingCharacters()
	{
		StringHelper::toInt64(LOG4CXX_STR("123abc"));
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


};


LOGUNIT_TEST_SUITE_REGISTRATION(StringHelperTestCase);
