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

#include "logunit.h"
#include <log4cxx/logger.h>
#include <log4cxx/jsonlayout.h>
#include <log4cxx/ndc.h>
#include <log4cxx/mdc.h>

#include <iostream>
#include <log4cxx/helpers/stringhelper.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

#if defined(__LOG4CXX_FUNC__)
	#undef __LOG4CXX_FUNC__
	#define __LOG4CXX_FUNC__ "X::X()"
#else
	#error __LOG4CXX_FUNC__ expected to be defined
#endif
/**
 * Test for JSONLayout.
 *
 */
LOGUNIT_CLASS(JSONLayoutTest), public JSONLayout
{
	LOGUNIT_TEST_SUITE(JSONLayoutTest);
	LOGUNIT_TEST(testGetContentType);
	LOGUNIT_TEST(testIgnoresThrowable);
	LOGUNIT_TEST(testAppendQuotedEscapedStringWithPrintableChars);
	LOGUNIT_TEST(testAppendQuotedEscapedStringWithControlChars);
	LOGUNIT_TEST(testAppendSerializedMDC);
	LOGUNIT_TEST(testAppendSerializedNDC);
	LOGUNIT_TEST(testFormat);
	LOGUNIT_TEST(testGetSetLocationInfo);
	LOGUNIT_TEST_SUITE_END();


public:
	/**
	 * Clear MDC and NDC before test.
	 */
	void setUp()
	{
		NDC::clear();
		MDC::clear();
	}

	/**
	 * Clear MDC and NDC after test.
	 */
	void tearDown()
	{
		setUp();
	}


public:
	/**
	 * Tests getContentType.
	 */
	void testGetContentType()
	{
		LogString expected(LOG4CXX_STR("application/json"));
		LogString actual(JSONLayout().getContentType());
		LOGUNIT_ASSERT(expected == actual);
	}

	/**
	 * Tests ignoresThrowable.
	 */
	void testIgnoresThrowable()
	{
		LOGUNIT_ASSERT_EQUAL(false, JSONLayout().ignoresThrowable());
	}

	/**
	 * Tests appendQuotedEscapedString with printable characters.
	 */
	void testAppendQuotedEscapedStringWithPrintableChars()
	{

		LogString s1("foo");                  /*  foo */
		LogString s2;
		appendQuotedEscapedString(s2, s1);    /*  "foo"  */
		LOGUNIT_ASSERT_EQUAL("\"foo\"", s2);

		LogString s3;
		appendQuotedEscapedString(s3, s2);    /*  "\"foo\""  */
		LOGUNIT_ASSERT_EQUAL("\"\\\"foo\\\"\"", s3);

		LogString t1("bar\"baz");             /*  bar"baz */
		LogString t2;
		appendQuotedEscapedString(t2, t1);    /*  "bar\"baz"  */
		LOGUNIT_ASSERT_EQUAL("\"bar\\\"baz\"", t2);

		LogString t3;
		appendQuotedEscapedString(t3, t2);    /*  "\"bar\\\"baz\""    */
		LOGUNIT_ASSERT_EQUAL("\"\\\"bar\\\\\\\"baz\\\"\"", t3);
	}

	/**
	 * Tests appendQuotedEscapedString with control characters.
	 */
	void testAppendQuotedEscapedStringWithControlChars()
	{

		LogString bs = {0x08};
		LogString bs_expected = {0x22, 0x5c, 'b', 0x22};      /* "\b" */
		LogString bs_escaped;
		appendQuotedEscapedString(bs_escaped, bs);
		LOGUNIT_ASSERT_EQUAL(bs_expected, bs_escaped);

		LogString tab = {0x09};
		LogString tab_expected = {0x22, 0x5c, 't', 0x22};     /* "\t" */
		LogString tab_escaped;
		appendQuotedEscapedString(tab_escaped, tab);
		LOGUNIT_ASSERT_EQUAL(tab_expected, tab_escaped);

		LogString newline = {0x0a};
		LogString newline_expected = {0x22, 0x5c, 'n', 0x22}; /* "\n" */
		LogString newline_escaped;
		appendQuotedEscapedString(newline_escaped, newline);
		LOGUNIT_ASSERT_EQUAL(newline_expected, newline_escaped);

		LogString ff = {0x0c};
		LogString ff_expected = {0x22, 0x5c, 'f', 0x22};      /* "\f" */
		LogString ff_escaped;
		appendQuotedEscapedString(ff_escaped, ff);
		LOGUNIT_ASSERT_EQUAL(ff_expected, ff_escaped);

		LogString cr = {0x0d};
		LogString cr_expected = {0x22, 0x5c, 'r', 0x22};      /* "\r" */
		LogString cr_escaped;
		appendQuotedEscapedString(cr_escaped, cr);
		LOGUNIT_ASSERT_EQUAL(cr_expected, cr_escaped);

	}

	/**
	 * Tests appendSerializedMDC.
	 */
	void testAppendSerializedMDC()
	{

		LoggingEventPtr event1 = new LoggingEvent(LOG4CXX_STR("Logger"),
			Level::getInfo(),
			LOG4CXX_STR("A message goes here."),
			LOG4CXX_LOCATION);

		MDC::put("key1", "value1");
		MDC::put("key2", "value2");

		LogString output1;
		LogString expected1 = ", \"context_map\": { "
			"\"key1\": \"value1\", \"key2\": \"value2\" }";

		appendSerializedMDC(output1, event1);

		LOGUNIT_ASSERT_EQUAL(expected1, output1);

	}


	/**
	 * Tests appendSerializedNDC.
	 */
	void testAppendSerializedNDC()
	{

		LoggingEventPtr event1 = new LoggingEvent(LOG4CXX_STR("Logger"),
			Level::getInfo(),
			LOG4CXX_STR("A message goes here."),
			LOG4CXX_LOCATION);

		NDC::push("one");
		NDC::push("two");
		NDC::push("three");

		LogString output1;
		LogString expected1 = ", \"context_stack\": [ \"one two three\" ]";

		appendSerializedNDC(output1, event1);

		LOGUNIT_ASSERT_EQUAL(expected1, output1);


	}


	/**
	 * Tests format.
	 */
	void testFormat()
	{

		Pool p;

		LoggingEventPtr event1 = new LoggingEvent(LOG4CXX_STR("Logger"),
			Level::getInfo(),
			LOG4CXX_STR("A message goes here."),
			LOG4CXX_LOCATION);

		LogString timestamp;
		helpers::ISO8601DateFormat dateFormat;
		dateFormat.format(timestamp, event1->getTimeStamp(), p);

		NDC::push("one");
		NDC::push("two");
		NDC::push("three");

		MDC::put("key1", "value1");
		MDC::put("key2", "value2");

		LogString output1;
		LogString expected1;

		expected1.append("{ \"timestamp\": \"")
		.append(timestamp)
		.append("\", ")
		.append("\"level\": \"INFO\", ")
		.append("\"logger\": \"Logger\", ")
		.append("\"message\": \"A message goes here.\"");

		appendSerializedMDC(expected1, event1);
		appendSerializedNDC(expected1, event1);

		expected1.append(" }\n");

		format(output1, event1, p);

		LOGUNIT_ASSERT_EQUAL(expected1, output1);

	}

	/**
	 * Tests getLocationInfo and setLocationInfo.
	 */
	void testGetSetLocationInfo()
	{
		JSONLayout layout;
		LOGUNIT_ASSERT_EQUAL(false, layout.getLocationInfo());
		layout.setLocationInfo(true);
		LOGUNIT_ASSERT_EQUAL(true, layout.getLocationInfo());
		layout.setLocationInfo(false);
		LOGUNIT_ASSERT_EQUAL(false, layout.getLocationInfo());
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(JSONLayoutTest);

