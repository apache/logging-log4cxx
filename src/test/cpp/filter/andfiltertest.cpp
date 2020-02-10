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

#include <log4cxx/filter/andfilter.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/filter/levelmatchfilter.h>
#include <log4cxx/filter/denyallfilter.h>
#include <log4cxx/filter/stringmatchfilter.h>
#include "../logunit.h"

using namespace log4cxx;
using namespace log4cxx::filter;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;


/**
 * Unit tests for AndFilter.
 */
LOGUNIT_CLASS(AndFilterTest)
{
	LOGUNIT_TEST_SUITE(AndFilterTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST(test5);
	LOGUNIT_TEST(test6);
	LOGUNIT_TEST_SUITE_END();

public:


	/**
	 * Check that AndFilter.decide() returns Filter.ACCEPT if no filters added.
	 */
	void test1()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.AndFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		FilterPtr filter(new AndFilter());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that AndFilter.decide() returns Filter.ACCEPT if
	 *    only nested filter returns Filter.ACCEPT.
	 */
	void test2()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.AndFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		AndFilterPtr filter(new AndFilter());
		LevelMatchFilterPtr filter1(new LevelMatchFilter());
		filter1->setLevelToMatch(LOG4CXX_STR("info"));
		Pool p;
		filter1->activateOptions(p);
		filter->addFilter(filter1);
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that AndFilter.decide() returns Filter.ACCEPT if
	 *    two nested filters return Filter.ACCEPT.
	 */
	void test3()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.AndFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		AndFilterPtr filter(new AndFilter());
		LevelMatchFilterPtr filter1(new LevelMatchFilter());
		filter1->setLevelToMatch(LOG4CXX_STR("info"));
		Pool p;
		filter1->activateOptions(p);
		filter->addFilter(filter1);
		LevelMatchFilterPtr filter2(new LevelMatchFilter());
		filter2->setLevelToMatch(LOG4CXX_STR("info"));
		filter2->activateOptions(p);
		filter->addFilter(filter2);
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that AndFilter.decide() returns Filter.DENY if
	 *    only nested filter returns Filter.ACCEPT
	 *    and acceptOnMatch is false.
	 */
	void test4()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.AndFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		AndFilterPtr filter(new AndFilter());
		LevelMatchFilterPtr filter1(new LevelMatchFilter());
		filter1->setLevelToMatch(LOG4CXX_STR("info"));
		Pool p;
		filter1->activateOptions(p);
		filter->addFilter(filter1);
		filter->setAcceptOnMatch(false);
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));
	}

	/**
	 * Check that AndFilter.decide() returns Filter.NEUTRAL if
	 *    nested filters return Filter.ACCEPT and Filter.DENY.
	 */
	void test5()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.AndFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		AndFilterPtr filter(new AndFilter());
		LevelMatchFilterPtr filter1(new LevelMatchFilter());
		filter1->setLevelToMatch(LOG4CXX_STR("info"));
		Pool p;
		filter1->activateOptions(p);
		filter->addFilter(filter1);
		FilterPtr filter2(new DenyAllFilter());
		filter2->activateOptions(p);
		filter->addFilter(filter2);
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}

	/**
	 * Check that AndFilter.decide() returns Filter.NEUTRAL if
	 *    nested filters return Filter.ACCEPT and Filter.NEUTRAL.
	 */
	void test6()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.AndFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		AndFilterPtr filter(new AndFilter());
		LevelMatchFilterPtr filter1(new LevelMatchFilter());
		filter1->setLevelToMatch(LOG4CXX_STR("info"));
		Pool p;
		filter1->activateOptions(p);
		filter->addFilter(filter1);
		FilterPtr filter2(new StringMatchFilter());
		filter2->activateOptions(p);
		filter->addFilter(filter2);
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}
};


LOGUNIT_TEST_SUITE_REGISTRATION(AndFilterTest);

