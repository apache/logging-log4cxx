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
#include <log4cxx/filter/locationinfofilter.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggingevent.h>
#include "../logunit.h"

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::filter;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

/**
 * Unit tests for LocationInfo.
 */
LOGUNIT_CLASS(LocationInfoFilterTest)
{
	LOGUNIT_TEST_SUITE(LocationInfoFilterTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST_SUITE_END();

public:

	/**
	 * Check that LocationInfoFilter.decide() returns Filter.NEUTRAL
	 *   when nothing is configured.
	 */
	void test1()
	{
		LocationInfo li("/path/to/foo.cpp",
						"foo.cpp",
						"exampleFun",
						50);
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("LocationInfoFilter"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				li));
		FilterPtr filter(new LocationInfoFilter());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}

	/**
	 * Check that LocationInfoFilter.decide() returns Filter.NEUTRAL
	 *   when line number does not match
	 */
	void test2()
	{
		LocationInfo li("/path/to/foo.cpp",
						"foo.cpp",
						"exampleFun",
						50);
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("LocationInfoFilter"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				li));
		LocationInfoFilterPtr filter(new LocationInfoFilter());
		filter->setLineNumber(10);
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}

	/**
	 * Check that LocationInfoFilter.decide() returns Filter.ACCEPT
	 * when the line number matches
	 */
	void test3()
	{
		LocationInfo li("/path/to/foo.cpp",
						"foo.cpp",
						"exampleFun",
						50);
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("LocationInfoFilter"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				li));
		LocationInfoFilterPtr filter(new LocationInfoFilter());
		filter->setLineNumber(50);
		filter->setAcceptOnMatch(true);
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that LocationInfoFilter.decide() returns Filter.ACCEPT
	 * when the line number and method name match
	 */
	void test4()
	{
		LocationInfo li("/path/to/foo.cpp",
						"foo.cpp",
						"exampleFun",
						50);
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("LocationInfoFilter"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				li));
		LocationInfoFilterPtr filter(new LocationInfoFilter());
		filter->setLineNumber(50);
		filter->setMethodName(LOG4CXX_STR("exampleFun"));
		filter->setAcceptOnMatch(true);
		filter->setMustMatchAll(true);
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(LocationInfoFilterTest);
