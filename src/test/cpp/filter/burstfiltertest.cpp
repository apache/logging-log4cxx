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

#include <log4cxx/filter/burstfilter.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggingevent.h>
#include "../vectorappender.h"
#include "../logunit.h"
#include <chrono>
#include <thread>

using namespace log4cxx;
using namespace log4cxx::filter;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;


/**
 * Unit tests for BurstFilter.
 */
LOGUNIT_CLASS(BurstFilterTest)
{
	LOGUNIT_TEST_SUITE(BurstFilterTest);
	LOGUNIT_TEST(testRegisteredClass);
	LOGUNIT_TEST(testDefaults);
	LOGUNIT_TEST(testSetOption);
	LOGUNIT_TEST(testInvalidOptions);
	LOGUNIT_TEST(testMaxBurst);
	LOGUNIT_TEST(testMoreSevereLevelIsNotLimited);
	LOGUNIT_TEST(testRefill);
	LOGUNIT_TEST(testActivateOptionsRefills);
	LOGUNIT_TEST(testPropertiesConfiguration);
	LOGUNIT_TEST_SUITE_END();

	LoggingEventPtr makeEvent(const LevelPtr& level)
	{
		return std::make_shared<LoggingEvent>
			( LOG4CXX_STR("org.apache.log4j.filter.BurstFilterTest")
			, level
			, LOG4CXX_STR("Hello, World")
			, LOG4CXX_LOCATION
			);
	}

	// The number of \c level events passed on by \c filter out of \c count events
	int passedCount(const BurstFilter& filter, const LevelPtr& level, int count)
	{
		auto event = makeEvent(level);
		int result = 0;
		for (int i = 0; i < count; ++i)
		{
			if (Filter::NEUTRAL == filter.decide(event))
				++result;
		}
		return result;
	}

public:
	void tearDown() override
	{
		LogManager::resetConfiguration();
	}

	/**
	 * Check the filter can be named in a configuration file.
	 */
	void testRegisteredClass()
	{
		LogString className(LOG4CXX_STR("org.apache.log4j.filter.BurstFilter"));
		auto& filterClass = Class::forName(className);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("BurstFilter"), filterClass.getName());
		ObjectPtr instance(filterClass.newInstance());
		LOGUNIT_ASSERT(log4cxx::cast<BurstFilter>(instance));
	}

	void testDefaults()
	{
		BurstFilter filter;
		LOGUNIT_ASSERT_EQUAL(Level::getWarn(), filter.getLevel());
		LOGUNIT_ASSERT_EQUAL(10, filter.getRate());
		LOGUNIT_ASSERT_EQUAL(100, filter.getMaxBurst());
		// The default MaxBurst follows the Rate
		filter.setRate(5);
		LOGUNIT_ASSERT_EQUAL(50, filter.getMaxBurst());
	}

	/**
	 * Check option names are case insensitive.
	 */
	void testSetOption()
	{
		BurstFilter filter;
		filter.setOption(LOG4CXX_STR("Level"), LOG4CXX_STR("INFO"));
		filter.setOption(LOG4CXX_STR("rate"), LOG4CXX_STR("3"));
		filter.setOption(LOG4CXX_STR("MAXBURST"), LOG4CXX_STR("7"));
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(Level::getInfo(), filter.getLevel());
		LOGUNIT_ASSERT_EQUAL(3, filter.getRate());
		LOGUNIT_ASSERT_EQUAL(7, filter.getMaxBurst());
		// An explicit MaxBurst does not follow the Rate
		filter.setRate(20);
		LOGUNIT_ASSERT_EQUAL(7, filter.getMaxBurst());
	}

	/**
	 * Check a value that is not a positive integer does not change the option.
	 */
	void testInvalidOptions()
	{
		BurstFilter filter;
		filter.setOption(LOG4CXX_STR("Rate"), LOG4CXX_STR("0"));
		filter.setOption(LOG4CXX_STR("Rate"), LOG4CXX_STR("-5"));
		filter.setOption(LOG4CXX_STR("Rate"), LOG4CXX_STR("fast"));
		filter.setOption(LOG4CXX_STR("MaxBurst"), LOG4CXX_STR("0"));
		filter.setOption(LOG4CXX_STR("MaxBurst"), LOG4CXX_STR("many"));
		filter.setRate(-1);
		filter.setMaxBurst(0);
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(10, filter.getRate());
		LOGUNIT_ASSERT_EQUAL(100, filter.getMaxBurst());
	}

	/**
	 * Check only MaxBurst events in a burst are passed on.
	 */
	void testMaxBurst()
	{
		BurstFilter filter;
		filter.setRate(1);
		filter.setMaxBurst(5);
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(5, passedCount(filter, Level::getInfo(), 20));
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter.decide(makeEvent(Level::getWarn())));
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter.decide(makeEvent(Level::getDebug())));
	}

	/**
	 * Check events more severe than Level are always passed on
	 * and do not use a token.
	 */
	void testMoreSevereLevelIsNotLimited()
	{
		BurstFilter filter;
		filter.setRate(1);
		filter.setMaxBurst(2);
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(20, passedCount(filter, Level::getError(), 20));
		LOGUNIT_ASSERT_EQUAL(20, passedCount(filter, Level::getFatal(), 20));
		LOGUNIT_ASSERT_EQUAL(2, passedCount(filter, Level::getWarn(), 20));
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter.decide(makeEvent(Level::getError())));

		filter.setLevel(Level::getError());
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(2, passedCount(filter, Level::getError(), 20));
		LOGUNIT_ASSERT_EQUAL(Filter::NEUTRAL, filter.decide(makeEvent(Level::getFatal())));
	}

	/**
	 * Check tokens are added at Rate per second up to MaxBurst.
	 */
	void testRefill()
	{
		BurstFilter filter;
		filter.setRate(20);
		filter.setMaxBurst(2);
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(2, passedCount(filter, Level::getInfo(), 10));
		// Wait long enough for more than MaxBurst tokens to be added
		std::this_thread::sleep_for(std::chrono::milliseconds(300));
		LOGUNIT_ASSERT_EQUAL(2, passedCount(filter, Level::getInfo(), 10));
	}

	void testActivateOptionsRefills()
	{
		BurstFilter filter;
		filter.setRate(1);
		filter.setMaxBurst(3);
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(3, passedCount(filter, Level::getInfo(), 10));
		filter.setMaxBurst(4);
		filter.activateOptions();
		LOGUNIT_ASSERT_EQUAL(4, passedCount(filter, Level::getInfo(), 10));
	}

	/**
	 * Check the filter limits the events written by an appender
	 * configured using a properties file.
	 */
	void testPropertiesConfiguration()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1"), LOG4CXX_STR("BurstFilter"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.Level"), LOG4CXX_STR("INFO"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.Rate"), LOG4CXX_STR("1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.MaxBurst"), LOG4CXX_STR("3"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, ConfigurationStatus::Configured);
		LoggerPtr root(Logger::getRootLogger());
		VectorAppenderPtr appender = log4cxx::cast<VectorAppender>(root->getAppender(LOG4CXX_STR("VECTOR1")));
		LOGUNIT_ASSERT(appender);
		auto filter = log4cxx::cast<BurstFilter>(appender->getFilter());
		LOGUNIT_ASSERT(filter);
		LOGUNIT_ASSERT_EQUAL(Level::getInfo(), filter->getLevel());
		LOGUNIT_ASSERT_EQUAL(1, filter->getRate());
		LOGUNIT_ASSERT_EQUAL(3, filter->getMaxBurst());
		for (int i = 0; i < 10; ++i)
			LOG4CXX_INFO(root, "Info message " << i);
		LOG4CXX_WARN(root, "Warn message");
		LOGUNIT_ASSERT_EQUAL(4, appender->getEventCount());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Info message 2"), appender->getEvent(3)->getRenderedMessage());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Warn message"), appender->getEvent(4)->getRenderedMessage());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(BurstFilterTest);
