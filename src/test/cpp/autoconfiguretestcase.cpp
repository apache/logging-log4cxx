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
#include <log4cxx/defaultconfigurator.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/pool.h>
#include <thread>
#include "apr_time.h"

#define LOGUNIT_TEST_THREADS(testName, threadCount) \
	class testName ## ThreadTestRegistration { \
		public: \
			testName ## ThreadTestRegistration() { \
				ThisFixture::getSuite()->addTest(#testName, &testName ## ThreadTestRegistration :: run); \
			} \
			static void run(abts_case* tc, void*) { \
				std::vector<std::thread> threads; \
				for (auto i = threadCount; 0 < i; --i) \
					threads.emplace_back( [tc]() { \
						LogUnit::runTest<ThisFixture>(tc, &ThisFixture::testName); \
					} ); \
				while (!threads.empty()) { \
					threads.back().join(); \
					threads.pop_back(); \
				} \
			} \
	} register ## testName ## ThreadTest

using namespace log4cxx;

LOGUNIT_CLASS(AutoConfigureTestCase)
{
	LOGUNIT_TEST_SUITE(AutoConfigureTestCase);
	LOGUNIT_TEST_THREADS(test1, 4);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST_SUITE_END();
#ifdef _DEBUG
	struct Fixture
	{
		Fixture() {
			helpers::LogLog::setInternalDebugging(true);
		}
	} suiteFixture;
#endif
	helpers::Pool m_pool;
	char m_buf[2048];
public:

	void setUp()
	{
		helpers::ByteBuffer bbuf(m_buf, sizeof(m_buf));
		auto sz = helpers::FileInputStream(LOG4CXX_STR("input/autoConfigureTest.properties")).read(bbuf);
		bbuf.position(0);
		bbuf.limit(sz);
		helpers::FileOutputStream(LOG4CXX_STR("output/autoConfigureTest.properties")).write(bbuf, m_pool);
	}
	void test1()
	{
		DefaultConfigurator::setConfigurationFileName(LOG4CXX_STR("output/autoConfigureTest.properties"));
		DefaultConfigurator::setConfigurationWatchSeconds(1);
		auto debugLogger = Logger::getLogger(LOG4CXX_STR("AutoConfig.test1"));
		LOGUNIT_ASSERT(debugLogger);
		LOGUNIT_ASSERT(!debugLogger->isDebugEnabled());
		auto rep = debugLogger->getLoggerRepository();
		LOGUNIT_ASSERT(rep);
		LOGUNIT_ASSERT(rep->isConfigured());
	}

	void test2()
	{
		auto debugLogger = Logger::getLogger(LOG4CXX_STR("AutoConfig.test2"));
		LOGUNIT_ASSERT(debugLogger);
		LOGUNIT_ASSERT(debugLogger->isDebugEnabled());
	}

	void test3()
	{
		auto debugLogger = Logger::getLogger(LOG4CXX_STR("AutoConfig.test3"));
		LOGUNIT_ASSERT(debugLogger);
		LOGUNIT_ASSERT(!debugLogger->isDebugEnabled());

		// Append a configuration for test3 logger
		helpers::ByteBuffer bbuf(m_buf, sizeof(m_buf));
		int sz = 0;
		for (auto p = "\nlog4j.logger.AutoConfig.test3=DEBUG\n"; *p; ++p)
		{
			bbuf.put(*p);
			++sz;
		}
		bbuf.position(0);
		bbuf.limit(sz);
		helpers::FileOutputStream of(LOG4CXX_STR("output/autoConfigureTest.properties"), true);
		of.write(bbuf, m_pool);
		of.flush(m_pool);
		of.close(m_pool);

		// wait 1.5 sec for the change to be noticed
		apr_sleep(1500000);
		LOGUNIT_ASSERT(debugLogger->isDebugEnabled());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(AutoConfigureTestCase);
