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

#include <log4cxx/helpers/properties.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/mdc.h>
#include <log4cxx/filter/denyallfilter.h>
#include <log4cxx/filter/levelmatchfilter.h>
#include "vectorappender.h"
#include "logunit.h"

using namespace log4cxx;
using namespace log4cxx::helpers;


LOGUNIT_CLASS(PropertyConfiguratorTest)
{
	LOGUNIT_TEST_SUITE(PropertyConfiguratorTest);
	LOGUNIT_TEST(testInherited);
	LOGUNIT_TEST(testNull);
	LOGUNIT_TEST(testAppenderThreshold);
	LOGUNIT_TEST(testInvalidAppenderBehavesNotConfigured);
	LOGUNIT_TEST(testAppenderFilters);
	LOGUNIT_TEST(testAppenderFilterOrder);
	LOGUNIT_TEST(testAppenderFilterOptionWithDots);
	LOGUNIT_TEST(testAppenderFilterWithoutClass);
	LOGUNIT_TEST(testSharedAppenderFilters);
	LOGUNIT_TEST_SUITE_END();

public:
	void testInherited()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("DEBUG,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.logger.org.apache.log4j.PropertyConfiguratorTest"), LOG4CXX_STR("inherited,VECTOR2"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR2"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr logger = Logger::getLogger("org.apache.log4j.PropertyConfiguratorTest");
		LOGUNIT_ASSERT_EQUAL((int) Level::DEBUG_INT,
			logger->getEffectiveLevel()->toInt());
		Logger::getRootLogger()->setLevel(Level::getError());
		LOGUNIT_ASSERT_EQUAL((int) Level::ERROR_INT,
			logger->getEffectiveLevel()->toInt());
		LogManager::resetConfiguration();
	}

	void testNull()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("DEBUG,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.logger.org.apache.log4j.PropertyConfiguratorTest"), LOG4CXX_STR("NuLL,VECTOR2"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR2"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr logger = Logger::getLogger("org.apache.log4j.PropertyConfiguratorTest");
		LOGUNIT_ASSERT_EQUAL((int) Level::DEBUG_INT,
			logger->getEffectiveLevel()->toInt());
		Logger::getRootLogger()->setLevel(Level::getError());
		LOGUNIT_ASSERT_EQUAL((int) Level::ERROR_INT,
			logger->getEffectiveLevel()->toInt());
		LogManager::resetConfiguration();
	}

	void testAppenderThreshold()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.threshold"), LOG4CXX_STR("WARN"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr root(Logger::getRootLogger());
		VectorAppenderPtr appender = log4cxx::cast<VectorAppender>(root->getAppender(LOG4CXX_STR("VECTOR1")));
		LOGUNIT_ASSERT_EQUAL((int) Level::WARN_INT, appender->getThreshold()->toInt());
		LOG4CXX_INFO(root, "Info message");
		LOG4CXX_WARN(root, "Warn message");
		LOG4CXX_WARN(root, "Error message");
		LOGUNIT_ASSERT_EQUAL(2, appender->getEventCount());
		LogManager::resetConfiguration();
	}

	void testInvalidAppenderBehavesNotConfigured()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("DEBUG,BAD"));
		props.put(LOG4CXX_STR("log4j.appender.BAD"), LOG4CXX_STR("does.not.Exist"));

		auto status = PropertyConfigurator::configure(props);

		// Expect: invalid appender config should result in NotConfigured
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::NotConfigured);

		// Repository should not be marked configured
		LOGUNIT_ASSERT_EQUAL(false, LogManager::getLoggerRepository()->isConfigured());

		// Root logger should have no appenders
		LoggerPtr root(Logger::getRootLogger());
		LOGUNIT_ASSERT_EQUAL((size_t)0, root->getAllAppenders().size());

		LogManager::resetConfiguration();
	}

	void testAppenderFilters()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1"), LOG4CXX_STR("LevelMatchFilter"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.LevelToMatch"), LOG4CXX_STR("WARN"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.AcceptOnMatch"), LOG4CXX_STR("true"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.2"), LOG4CXX_STR("org.apache.log4j.varia.DenyAllFilter"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr root(Logger::getRootLogger());
		VectorAppenderPtr appender = log4cxx::cast<VectorAppender>(root->getAppender(LOG4CXX_STR("VECTOR1")));
		LOGUNIT_ASSERT(appender);
		auto first = log4cxx::cast<filter::LevelMatchFilter>(appender->getFilter());
		LOGUNIT_ASSERT(first);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("WARN"), first->getLevelToMatch());
		LOGUNIT_ASSERT_EQUAL(true, first->getAcceptOnMatch());
		auto second = log4cxx::cast<filter::DenyAllFilter>(first->getNext());
		LOGUNIT_ASSERT(second);
		LOGUNIT_ASSERT(!second->getNext());
		LOG4CXX_INFO(root, "Info message");
		LOG4CXX_WARN(root, "Warn message");
		LOG4CXX_ERROR(root, "Error message");
		LOGUNIT_ASSERT_EQUAL(1, appender->getEventCount());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Warn message"), appender->getEvent(1)->getRenderedMessage());
		LogManager::resetConfiguration();
	}

	void testAppenderFilterOrder()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		// Filters are ordered by identifier string, so "10" is consulted before "2"
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.2"), LOG4CXX_STR("DenyAllFilter"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.10"), LOG4CXX_STR("LevelMatchFilter"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.10.LevelToMatch"), LOG4CXX_STR("ERROR"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.10.AcceptOnMatch"), LOG4CXX_STR("true"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr root(Logger::getRootLogger());
		VectorAppenderPtr appender = log4cxx::cast<VectorAppender>(root->getAppender(LOG4CXX_STR("VECTOR1")));
		LOGUNIT_ASSERT(appender);
		auto first = log4cxx::cast<filter::LevelMatchFilter>(appender->getFilter());
		LOGUNIT_ASSERT(first);
		LOGUNIT_ASSERT(log4cxx::cast<filter::DenyAllFilter>(first->getNext()));
		LOG4CXX_WARN(root, "Warn message");
		LOG4CXX_ERROR(root, "Error message");
		LOGUNIT_ASSERT_EQUAL(1, appender->getEventCount());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Error message"), appender->getEvent(1)->getRenderedMessage());
		LogManager::resetConfiguration();
	}

	void testAppenderFilterOptionWithDots()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1"), LOG4CXX_STR("org.apache.log4j.filter.MapFilter"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.user.ip"), LOG4CXX_STR("127.0.0.1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.user.name"), LOG4CXX_STR("test"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.Operator"), LOG4CXX_STR("AND"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.AcceptOnMatch"), LOG4CXX_STR("false"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr root(Logger::getRootLogger());
		VectorAppenderPtr appender = log4cxx::cast<VectorAppender>(root->getAppender(LOG4CXX_STR("VECTOR1")));
		LOGUNIT_ASSERT(appender);
		{
			MDC ip(LOG4CXX_STR("user.ip"), LOG4CXX_STR("127.0.0.1"));
			LOG4CXX_INFO(root, "Message from another user");
			MDC name(LOG4CXX_STR("user.name"), LOG4CXX_STR("test"));
			LOG4CXX_INFO(root, "Message from the excluded user");
		}
		LOGUNIT_ASSERT_EQUAL(1, appender->getEventCount());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Message from another user"), appender->getEvent(1)->getRenderedMessage());
		LogManager::resetConfiguration();
	}

	void testAppenderFilterWithoutClass()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1.LevelToMatch"), LOG4CXX_STR("WARN"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.2"), LOG4CXX_STR("does.not.Exist"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr root(Logger::getRootLogger());
		VectorAppenderPtr appender = log4cxx::cast<VectorAppender>(root->getAppender(LOG4CXX_STR("VECTOR1")));
		LOGUNIT_ASSERT(appender);
		LOGUNIT_ASSERT(!appender->getFilter());
		LOG4CXX_INFO(root, "Info message");
		LOGUNIT_ASSERT_EQUAL(1, appender->getEventCount());
		LogManager::resetConfiguration();
	}

	void testSharedAppenderFilters()
	{
		Properties props;
		props.put(LOG4CXX_STR("log4j.rootLogger"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.logger.org.apache.log4j.PropertyConfiguratorTest"), LOG4CXX_STR("ALL,VECTOR1"));
		props.put(LOG4CXX_STR("log4j.additivity.org.apache.log4j.PropertyConfiguratorTest"), LOG4CXX_STR("false"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1"), LOG4CXX_STR("org.apache.log4j.VectorAppender"));
		props.put(LOG4CXX_STR("log4j.appender.VECTOR1.filter.1"), LOG4CXX_STR("DenyAllFilter"));
		auto status = PropertyConfigurator::configure(props);
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
		LoggerPtr logger = Logger::getLogger("org.apache.log4j.PropertyConfiguratorTest");
		VectorAppenderPtr appender = log4cxx::cast<VectorAppender>(logger->getAppender(LOG4CXX_STR("VECTOR1")));
		LOGUNIT_ASSERT(appender);
		LOGUNIT_ASSERT_EQUAL(appender, log4cxx::cast<VectorAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("VECTOR1"))));
		// The filter is added once only
		LOGUNIT_ASSERT(log4cxx::cast<filter::DenyAllFilter>(appender->getFilter()));
		LOGUNIT_ASSERT(!appender->getFilter()->getNext());
		LogManager::resetConfiguration();
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(PropertyConfiguratorTest);
