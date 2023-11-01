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
#include <log4cxx/filter/loggermatchfilter.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggingevent.h>
#include "../logunit.h"

using namespace log4cxx;
using namespace log4cxx::filter;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;


/**
 * Unit tests for LoggerMatchFilter.
 */
LOGUNIT_CLASS(LoggerMatchFilterTest)
{
	LOGUNIT_TEST_SUITE(LoggerMatchFilterTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST_SUITE_END();

public:
	/**
	 * Check that LoggerMatchFilter::decide() with unspecified level
	 *    returns Filter::ACCEPT for root logger.
	 */
	void test1()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("root"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		FilterPtr filter(new LoggerMatchFilter());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

	/**
	 * Check that LoggerMatchFilter::decide() with unspecified level
	 *    returns Filter::DENY for root logger when accept on match is false.
	 */
	void test2()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("root"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LoggerMatchFilterPtr filter(new LoggerMatchFilter());
		filter->setAcceptOnMatch(false);
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));
	}

	/**
	 * Check that LoggerMatchFilter::decide() with unspecified level
	 *    returns Filter::NEUTRAL for non-root logger.
	 */
	void test3()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.LoggerMatchFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		FilterPtr filter(new LoggerMatchFilter());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter->decide(event));
	}

	/**
	 * Check that LoggerMatchFilter::decide()
	 *    returns Filter::ACCEPT for matching logger.
	 */
	void test4()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.LoggerMatchFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		LoggerMatchFilterPtr filter(new LoggerMatchFilter());
		filter->setLoggerToMatch(LOG4CXX_STR("org.apache.log4j.filter.LoggerMatchFilterTest"));
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::ACCEPT, filter->decide(event));
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(LoggerMatchFilterTest);
