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
#include "../logunit.h"
#include "../insertwide.h"
#include <log4cxx/logmanager.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/private/boost-std-configuration.h>
#include <log4cxx/helpers/strftimedateformat.h>
#include <log4cxx/helpers/date.h>

using namespace log4cxx;

auto getLogger(const std::string& name) -> LoggerPtr {
    static struct log4cxx_initializer {
        log4cxx_initializer() {
			xml::DOMConfigurator::configure("input/rolling/multiprocess.xml");
        }
        ~log4cxx_initializer() {
            LogManager::shutdown();
        }
    } initAndShutdown;
    return name.empty()
        ? LogManager::getRootLogger()
        : LogManager::getLogger(name);
}

LOGUNIT_CLASS(MultiprocessRollingTest)
{
	LOGUNIT_TEST_SUITE(MultiprocessRollingTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST_SUITE_END();

public:
	/**
	 * Test a numeric rolling policy with a log level based trigger.
	 */
	void test1()
	{
		auto logger = getLogger("Test1");
		for (int i = 0; i < 25; i++)
		{
			char msg[10];
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_SECURE_LIB__)
			strcpy_s(msg, sizeof msg, "Hello---?");
#else
			strcpy(msg, "Hello---?");
#endif

			if (i < 10)
			{
				msg[8] = (char) ('0' + i);
				LOG4CXX_DEBUG(logger, msg);
			}
			else if (i < 100)
			{
				msg[7] = (char) ('0' + (i / 10));
				msg[8] = (char) ('0' + (i % 10));

				if ((i % 10) == 0)
				{
					LOG4CXX_WARN(logger, msg);
				}
				else
				{
					LOG4CXX_DEBUG(logger, msg);
				}
			}
		}

		LogString baseName = LOG4CXX_STR("output/rolling/multiprocess-test");
		LOGUNIT_ASSERT_EQUAL(true,
			Compare::compare(baseName + LOG4CXX_STR(".log"), LogString(LOG4CXX_STR("witness/rolling/multiprocess-test.log"))));
		LOGUNIT_ASSERT_EQUAL(true,
			Compare::compare(baseName + LOG4CXX_STR(".0"), LogString(LOG4CXX_STR("witness/rolling/multiprocess-test.0"))));
		LOGUNIT_ASSERT_EQUAL(true,
			Compare::compare(baseName + LOG4CXX_STR(".1"), LogString(LOG4CXX_STR("witness/rolling/multiprocess-test.1"))));
	}

	/**
	 * Test a time based rolling policy with a sized based trigger.
	 */
	void test2()
	{
		LogString expectedPrefix = LOG4CXX_STR("multiprocess-dated-");
		// remove any previously generated files
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			LogString filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() < filename.size() &&
				filename.substr(0, expectedPrefix.size()) == expectedPrefix)
				std::filesystem::remove(dir_entry);
		}
		auto logger = getLogger("Test2");
		auto approxBytesPerLogEvent = 40 + 23;
		auto requiredLogFileCount = 3;
		auto approxBytesPerLogFile = 1000;
		auto requiredLogEventCount = (approxBytesPerLogFile * requiredLogFileCount + approxBytesPerLogEvent - 1) / approxBytesPerLogEvent;
		for ( int x = 0; x < requiredLogEventCount; x++ )
		{
			LOG4CXX_INFO( logger, "This is test message " << x );
		}

		// Count rolled files
		helpers::Pool p;
		helpers::StrftimeDateFormat("%Y-%m-%d").format(expectedPrefix, helpers::Date::currentTime(), p);
		int fileCount = 0;
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			LogString filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() < filename.size() &&
				filename.substr(0, expectedPrefix.size()) == expectedPrefix)
				++fileCount;
		}
		LOGUNIT_ASSERT(1 < fileCount);
	}

private:
	/**
	 *   Common aspects of test1 and test2
	 */
	void common(const LogString & baseName)
	{

	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(MultiprocessRollingTest);

