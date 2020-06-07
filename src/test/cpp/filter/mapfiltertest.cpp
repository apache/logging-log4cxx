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
#include <log4cxx/filter/mapfilter.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggingevent.h>
#include "../logunit.h"

using namespace log4cxx;
using namespace log4cxx::filter;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

/**
 * Unit tests for MapFilter.
 */
LOGUNIT_CLASS(MapFilterTest)
{
	LOGUNIT_TEST_SUITE(MapFilterTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST_SUITE_END();

public:

	/**
	 * Check that MapFilter.decide() returns Filter.NEUTRAL
	 *   when there are no map entries specified.
	 */
	void test1()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("MapFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		FilterPtr filter(new MapFilter());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}

	/**
	 * Check that MapFilter.decide() returns Filter.ACCEPT or Filter.DENY
	 *   based on Accept on Match setting when key/value does not match
	 */
	void test2()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("MapFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		MDC::put(LOG4CXX_STR("my.ip"), LOG4CXX_STR("localhost"));
		MapFilterPtr filter(new MapFilter());
		filter->setKeyValue(LOG4CXX_STR("my.ip"), LOG4CXX_STR("127.0.0.1"));
		Pool p;
		filter->activateOptions(p);

		filter->setAcceptOnMatch(true);
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));

		filter->setAcceptOnMatch(false);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that MapFilter.decide() returns Filter.ACCEPT or Filter.DENY
	 *   based on Accept on Match setting when key/value matches
	 */
	void test3()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("MapFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		MDC::put(LOG4CXX_STR("my.ip"), LOG4CXX_STR("127.0.0.1"));
		MapFilterPtr filter(new MapFilter());
		filter->setKeyValue(LOG4CXX_STR("my.ip"), LOG4CXX_STR("127.0.0.1"));
		Pool p;
		filter->activateOptions(p);

		filter->setAcceptOnMatch(true);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));

		filter->setAcceptOnMatch(false);
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));
	}

	/**
	 * Check that MapFilter.decide() ANDs or ORs multiple key/values
	 *   based on operator setting
	 */
	void test4()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("MapFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		MDC::put(LOG4CXX_STR("my.ip"), LOG4CXX_STR("127.0.0.1"));
		MDC::put(LOG4CXX_STR("my.name"), LOG4CXX_STR("Test"));
		MapFilterPtr filter(new MapFilter());
		filter->setKeyValue(LOG4CXX_STR("my.ip"), LOG4CXX_STR("127.0.0.1"));
		filter->setKeyValue(LOG4CXX_STR("my.name"), LOG4CXX_STR("Unknown"));
		filter->setAcceptOnMatch(true);
		Pool p;
		filter->activateOptions(p);

		filter->setMustMatchAll(true);      // AND T/F
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));      // does not match second

		filter->setMustMatchAll(false); // OR T/F
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));    // matches first

		filter->setKeyValue(LOG4CXX_STR("my.name"), LOG4CXX_STR("Test"));

		filter->setMustMatchAll(true);      // AND T/T
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));    // matches all

		filter->setMustMatchAll(false); // OR T/T
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));    // matches first

		filter->setKeyValue(LOG4CXX_STR("my.ip"), LOG4CXX_STR("localhost"));

		filter->setMustMatchAll(true);      // AND F/T
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));      // does not match first

		filter->setMustMatchAll(false); // OR F/T
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));    // matches second

		filter->setKeyValue(LOG4CXX_STR("my.name"), LOG4CXX_STR("Unkonwn"));

		filter->setMustMatchAll(true);      // AND F/F
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));      // does not match first

		filter->setMustMatchAll(false); // OR F/F
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));      // matches none
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(MapFilterTest);


