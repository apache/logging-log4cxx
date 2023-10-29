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

#include "../logunit.h"
#include "util/compare.h"
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/logmanager.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;


LOGUNIT_CLASS(ThreadUtilityTest)
{
	LOGUNIT_TEST_SUITE(ThreadUtilityTest);
	LOGUNIT_TEST(testNullFunctions);
	LOGUNIT_TEST(testCustomFunctions);
	LOGUNIT_TEST(testDefaultFunctions);
#if LOG4CXX_HAS_PTHREAD_SETNAME || defined(WIN32)
	LOGUNIT_TEST(testThreadNameLogging);
#endif
	LOGUNIT_TEST_SUITE_END();
#ifdef _DEBUG
	struct Fixture
	{
		Fixture() {
			LogLog::setInternalDebugging(true);
		}
	} suiteFixture;
#endif

public:
	void testNullFunctions()
	{
		auto thrUtil = ThreadUtility::instance();

		thrUtil->configureFuncs( nullptr, nullptr, nullptr );

		std::thread t = thrUtil->createThread( LOG4CXX_STR("FooName"), []() {} );

		t.join();
	}

	void testCustomFunctions()
	{
		auto thrUtil = ThreadUtility::instance();
		int num_pre = 0;
		int num_started = 0;
		int num_post = 0;

		thrUtil->configureFuncs(
			[&num_pre]()
		{
			num_pre++;
		},
		[&num_started]( LogString,
			std::thread::id,
			std::thread::native_handle_type )
		{
			num_started++;
		},
		[&num_post]()
		{
			num_post++;
		}
		);

		std::thread t = thrUtil->createThread( LOG4CXX_STR("FooName"), []() {} );

		t.join();

		LOGUNIT_ASSERT_EQUAL( num_pre, 1 );
		LOGUNIT_ASSERT_EQUAL( num_started, 1 );
		LOGUNIT_ASSERT_EQUAL( num_post, 1 );
	}

	void testDefaultFunctions()
	{
		ThreadUtility::configure( ThreadConfigurationType::BlockSignalsAndNameThread );

		auto thrUtil = ThreadUtility::instance();

		std::thread t = thrUtil->createThread( LOG4CXX_STR("FooName"), []() {} );

		t.join();
	}

	void testThreadNameLogging()
	{
		auto layout = std::make_shared<PatternLayout>(LOG4CXX_STR("%T %m%n"));
		LogString logFileName(LOG4CXX_STR("output/threadnametestcase.log"));
		AppenderPtr appender(new FileAppender(layout, logFileName, false));
		auto logger = LogManager::getRootLogger();
		logger->addAppender(appender);
		std::thread t = ThreadUtility::instance()->createThread( LOG4CXX_STR("FooName"), [logger]() {
			LOG4CXX_DEBUG(logger, "Test message");
		});
		t.join();
		LOGUNIT_ASSERT(Compare::compare(logFileName, LOG4CXX_FILE("witness/threadnametestcase.1")));
	}
};


LOGUNIT_TEST_SUITE_REGISTRATION(ThreadUtilityTest);

