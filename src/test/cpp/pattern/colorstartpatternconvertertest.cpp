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

#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/level.h>

#include "../testchar.h"
#include "../insertwide.h"
#include "../logunit.h"
#include <log4cxx/spi/loggerrepository.h>

#include <log4cxx/helpers/loglog.h>
#include <log4cxx/pattern/colorstartpatternconverter.h>

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>
#include <thread>


using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::pattern;


LOGUNIT_CLASS(ColorStartPatternConverterTestCase)
{
	LOGUNIT_TEST_SUITE(ColorStartPatternConverterTestCase);
	LOGUNIT_TEST(testParseForeground);
	LOGUNIT_TEST(testParseBackground);
	LOGUNIT_TEST(testParseForegroundAndBackground);
	LOGUNIT_TEST(testParseUnbalancedParens1);
	LOGUNIT_TEST(testParseUnbalancedParens2);
	LOGUNIT_TEST(testParseUnbalancedParens3);
	LOGUNIT_TEST(testANSICode);
	LOGUNIT_TEST(testInvalidANSICode);
	LOGUNIT_TEST(testUnterminatedANSICode);
	LOGUNIT_TEST(testForegroundBackgroundBlink);
	LOGUNIT_TEST(testClearColor);
	LOGUNIT_TEST_SUITE_END();


public:
	void setUp()
	{
	}

	void tearDown()
	{
	}

	void testParseForeground()
	{
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("fg(red)"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[;31m"), outputString);
	}

	void testParseBackground()
	{
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("bg(red)"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[;41m"), outputString);
	}

	void testParseForegroundAndBackground()
	{
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("fg(green)|bg(red)"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[;32;41m"), outputString);
	}

	void testParseUnbalancedParens1(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("fg(green))"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[m"), outputString);
	}

	void testParseUnbalancedParens2(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("fg(green"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[m"), outputString);
	}

	void testParseUnbalancedParens3(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("fg(green|bg(red)"));
		colorPatternConverter.format(event, outputString, p);

		// The background should be parsed correctly, but since the foreground
		// is bad it will not work
		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[;41m"), outputString);
	}

	void testANSICode(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("\\x1b[34;40m"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[34;40m"), outputString);
	}

	void testInvalidANSICode(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("\\x1b"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR(""), outputString);
	}

	void testUnterminatedANSICode(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("\\x1b[31"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR(""), outputString);
	}

	void testForegroundBackgroundBlink(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("fg(white)|bg(black)|blinking"));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("\x1b[;37;40;5m"), outputString);
	}

	void testClearColor(){
		ColorStartPatternConverter colorPatternConverter;
		LogString outputString;
		Pool p;

		LoggingEventPtr event= LoggingEventPtr(new LoggingEvent(
												   LOG4CXX_STR("org.foobar"),
												   Level::getInfo(),
												   LOG4CXX_STR("msg 1"),
												   LOG4CXX_LOCATION));

		colorPatternConverter.setInfoColor(LOG4CXX_STR("fg(white)|bg(black)|blinking"));
		colorPatternConverter.setInfoColor(LOG4CXX_STR(""));
		colorPatternConverter.format(event, outputString, p);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR(""), outputString);
	}

};

#if !defined(_MSC_VER) || _MSC_VER > 1200
	LOGUNIT_TEST_SUITE_REGISTRATION(ColorStartPatternConverterTestCase);
#endif
