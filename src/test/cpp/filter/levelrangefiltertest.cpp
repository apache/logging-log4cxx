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
#include <log4cxx/filter/levelrangefilter.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggingevent.h>
#include "../logunit.h"

using namespace log4cxx;
using namespace log4cxx::filter;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;


/**
 * Unit tests for LevelRangeFilter.
 */
LOGUNIT_CLASS(LevelRangeFilterTest)
{
	LOGUNIT_TEST_SUITE(LevelRangeFilterTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST(test5);
	LOGUNIT_TEST(test6);
	LOGUNIT_TEST_SUITE_END();

public:
	/**
	 * Check that LevelRangefilter->decide() returns Filter::DENY
	 *     when event level is below min level.
	 */
	void test1()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.Filter::LevelRangeFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LevelRangeFilterPtr filter(new LevelRangeFilter());
		filter->setLevelMin(Level::getWarn());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));
	}

	/**
	 * Check that LevelRangefilter->decide() returns Filter::DENY
	 *    when event level is above max level.
	 */
	void test2()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.Filter::LevelRangeFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LevelRangeFilterPtr filter(new LevelRangeFilter());
		filter->setLevelMax(Level::getDebug());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));
	}

	/**
	 * Check that LevelRangefilter->decide() returns Filter::ACCEPT
	 *    when event level is above min level.
	 */
	void test3()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.Filter::LevelRangeFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LevelRangeFilterPtr filter(new LevelRangeFilter());
		filter->setLevelMin(Level::getDebug());
		filter->setAcceptOnMatch(true);
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that LevelRangefilter->decide() returns Filter::ACCEPT
	 *    when event level is below max level.
	 */
	void test4()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.Filter::LevelRangeFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LevelRangeFilterPtr filter(new LevelRangeFilter());
		filter->setLevelMax(Level::getError());
		filter->setAcceptOnMatch(true);
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that LevelRangeFilter::decide() returns Filter::NEUTRAL
	 *    when event level is above min level and accept on match is false.
	 */
	void test5()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.Filter::LevelRangeFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LevelRangeFilterPtr filter(new LevelRangeFilter());
		filter->setLevelMin(Level::getDebug());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}

	/**
	 * Check that LevelRangeFilter::decide() returns Filter::NEUTRAL
	 *    when event level is below max level and accept on match is false.
	 */
	void test6()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.Filter::LevelRangeFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LevelRangeFilterPtr filter(new LevelRangeFilter());
		filter->setLevelMax(Level::getError());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(LevelRangeFilterTest);

