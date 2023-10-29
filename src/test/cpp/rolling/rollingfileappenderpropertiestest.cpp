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
#include "../util/compare.h"
#include "../insertwide.h"
#include "../logunit.h"
#include <apr_time.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/rolling/fixedwindowrollingpolicy.h>
#include <log4cxx/rolling/sizebasedtriggeringpolicy.h>
#include <log4cxx/filter/levelrangefilter.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/fileoutputstream.h>


using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::xml;
using namespace LOG4CXX_NS::filter;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::rolling;

/**
 *
 */
LOGUNIT_CLASS(RollingFileAppenderPropertiesTest)
{
	LOGUNIT_TEST_SUITE(RollingFileAppenderPropertiesTest);
	LOGUNIT_TEST(testIsOptionHandler);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST(testRollingFromProperties);
	LOGUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
	}

	void tearDown()
	{
		LogManager::shutdown();
	}

	/**
	 * Test basic rolling functionality.
	 */
	void test1()
	{
		PropertyConfigurator::configure(File("input/rolling/obsoleteRFA1.properties"));

		// Make sure that the configured values are what we expect
		auto appender = LogManager::getRootLogger()->getAppender(LOG4CXX_STR("testAppender"));
		LOGUNIT_ASSERT(appender);

		auto rfa = cast<RollingFileAppender>(appender);
		LOGUNIT_ASSERT(rfa);

		LOGUNIT_ASSERT_EQUAL(3, rfa->getMaxBackupIndex());
		LOGUNIT_ASSERT_EQUAL(100, static_cast<int>(rfa->getMaximumFileSize()));

		logchar msg[] = { 'H', 'e', 'l', 'l', 'o', '-', '-', '-', '?', 0};
		auto logger = Logger::getLogger("RollingFileAppenderTest");

		// Write exactly 10 bytes with each log
		for (int i = 0; i < 25; i++)
		{
			apr_sleep(100000);

			if (i < 10)
			{
				msg[8] = (logchar) ('0' + i);
				LOG4CXX_DEBUG(logger, msg);
			}
			else if (i < 100)
			{
				msg[7] = (logchar) ('0' + i / 10);
				msg[8] = (logchar) ('0' + i % 10);
				LOG4CXX_DEBUG(logger, msg);
			}
		}

		Pool p;
		LOGUNIT_ASSERT_EQUAL(true, File("output/obsoleteRFA-test1.log").exists(p));
		LOGUNIT_ASSERT_EQUAL(true, File("output/obsoleteRFA-test1.log.1").exists(p));
	}

	/**
	 * Test basic rolling functionality.
	 */
	void test2()
	{
		auto layout = std::make_shared <PatternLayout>(LOG4CXX_STR("%m\n"));
		auto rfa = std::make_shared<RollingFileAppender>();
		rfa->setName(LOG4CXX_STR("ROLLING"));
		rfa->setLayout(layout);
		rfa->setOption(LOG4CXX_STR("append"), LOG4CXX_STR("false"));
		rfa->setMaximumFileSize(100);
		rfa->setFile(LOG4CXX_STR("output/obsoleteRFA-test2.log"));
		Pool p;
		rfa->activateOptions(p);
		auto root = Logger::getRootLogger();
		root->addAppender(rfa);

		logchar msg[] = { 'H', 'e', 'l', 'l', 'o', '-', '-', '-', '?', 0};
		auto logger = Logger::getLogger("org.apache.logj4.ObsoleteRollingFileAppenderTest");

		// Write exactly 10 bytes with each log
		for (int i = 0; i < 25; i++)
		{
			apr_sleep(100000);

			if (i < 10)
			{
				msg[8] = (logchar) ('0' + i);
				LOG4CXX_DEBUG(logger, msg);
			}
			else if (i < 100)
			{
				msg[7] = (logchar) ('0' + i / 10);
				msg[8] = (logchar) ('0' + i % 10);
				LOG4CXX_DEBUG(logger, msg);
			}
		}

		LOGUNIT_ASSERT_EQUAL(true, File("output/obsoleteRFA-test2.log").exists(p));
		LOGUNIT_ASSERT_EQUAL(true, File("output/obsoleteRFA-test2.log.1").exists(p));
	}

	/**
	 * Test propertyfile configured time based rolling functionality.
	 */
	void test3()
	{
		PropertyConfigurator::configure(File("input/rolling/obsoleteDRFA1.properties"));

		int preCount = getFileCount("output", LOG4CXX_STR("obsoleteDRFA-test1.log."));
		LoggerPtr logger(Logger::getLogger("DailyRollingFileAppenderTest"));

		char msg[11];
		strncpy(msg, "Hello---??", sizeof(msg));

		for (int i = 0; i < 25; i++)
		{
			apr_sleep(100000);
			msg[8] = (char) ('0' + (i / 10));
			msg[9] = (char) ('0' + (i % 10));
			LOG4CXX_DEBUG(logger, msg);
		}

		int postCount = getFileCount("output", LOG4CXX_STR("obsoleteDRFA-test1.log."));
		LOGUNIT_ASSERT_EQUAL(true, postCount > preCount);
	}

	/**
	 * Test programatically configured time based rolling functionality.
	 */
	void test4()
	{
		PatternLayoutPtr layout(new PatternLayout(LOG4CXX_STR("%m%n")));
		auto rfa = std::make_shared<RollingFileAppender>();
		rfa->setName(LOG4CXX_STR("ROLLING"));
		rfa->setLayout(layout);
		rfa->setAppend(false);
		rfa->setFile(LOG4CXX_STR("output/obsoleteDRFA-test2.log"));
		rfa->setDatePattern(LOG4CXX_STR("'.'yyyy-MM-dd-HH_mm_ss"));
		Pool p;
		rfa->activateOptions(p);
		LoggerPtr root(Logger::getRootLogger());
		root->addAppender(rfa);
		LoggerPtr logger(Logger::getLogger("ObsoleteDailyRollingAppenderTest"));

		int preCount = getFileCount("output", LOG4CXX_STR("obsoleteDRFA-test2.log."));

		char msg[11];
		strncpy(msg, "Hello---??", sizeof(msg));

		for (int i = 0; i < 25; i++)
		{
			apr_sleep(100000);
			msg[8] = (char) ('0' + i / 10);
			msg[9] = (char) ('0' + i % 10);
			LOG4CXX_DEBUG(logger, msg);
		}

		int postCount = getFileCount("output", LOG4CXX_STR("obsoleteDRFA-test2.log."));
		LOGUNIT_ASSERT_EQUAL(true, postCount > preCount);
	}

	/**
	 *  Tests if class is declared to support the OptionHandler interface.
	 *  See LOGCXX-136.
	 */
	void testIsOptionHandler()
	{
		auto rfa = std::make_shared<RollingFileAppender>();
		LOGUNIT_ASSERT_EQUAL(true, rfa->instanceof(LOG4CXX_NS::spi::OptionHandler::getStaticClass()));
	}

	void testRollingFromProperties(){
		// Load the properties from the file and make sure that the configured values are
		// what we expect
		PropertyConfigurator::configure(LOG4CXX_FILE("input/rolling/rollingFileAppenderFromProperties.properties"));

		auto appender = LogManager::getRootLogger()->getAppender(LOG4CXX_STR("FILE"));
		LOGUNIT_ASSERT(appender);

		auto rfa = cast<RollingFileAppender>(appender);
		LOGUNIT_ASSERT(rfa);

		FixedWindowRollingPolicyPtr fixedWindowRolling = cast<FixedWindowRollingPolicy>(rfa->getRollingPolicy());
		LOGUNIT_ASSERT(fixedWindowRolling);

		auto sizeBasedPolicy = cast<SizeBasedTriggeringPolicy>(rfa->getTriggeringPolicy());
		LOGUNIT_ASSERT(sizeBasedPolicy);

		LOGUNIT_ASSERT_EQUAL(3, fixedWindowRolling->getMaxIndex());
		LOGUNIT_ASSERT_EQUAL(100, static_cast<int>(sizeBasedPolicy->getMaxFileSize()));
	}

private:
	static int getFileCount(const char* dir, const LogString & initial)
	{
		Pool p;
		std::vector<LogString> files(File(dir).list(p));
		int count = 0;

		for (size_t i = 0; i < files.size(); i++)
		{
			if (StringHelper::startsWith(files[i], initial))
			{
				count++;
			}
		}

		return count;
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(RollingFileAppenderPropertiesTest);
