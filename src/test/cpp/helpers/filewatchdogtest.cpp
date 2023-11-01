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
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/filewatchdog.h>
#include "../logunit.h"
#include "apr_time.h"

using namespace log4cxx;
using namespace log4cxx::helpers;


/**
 *
 * FileWatchdog tests.
 */
LOGUNIT_CLASS(FileWatchdogTest)
{
	LOGUNIT_TEST_SUITE(FileWatchdogTest);
	LOGUNIT_TEST(testShutdownDelay);
	LOGUNIT_TEST_SUITE_END();

private:
	class MockWatchdog : public FileWatchdog
	{
		public:
			MockWatchdog(const File& file) : FileWatchdog(file)
			{
			}

			void doOnChange()
			{
			}
	};

public:

	/**
	 *  Tests that FileWatchdog will respond to a shutdown request more rapidly
	 *     than waiting out its delay.
	 */
	void testShutdownDelay()
	{
		apr_time_t start = apr_time_now();
		{
			MockWatchdog dog(File(LOG4CXX_STR("input/patternlayout1.properties")));
			dog.start();
			//   wait 50 ms for thread to get rolling
			apr_sleep(50000);
		}
		apr_time_t delta = apr_time_now() - start;
		LOGUNIT_ASSERT(delta < 30000000);
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(FileWatchdogTest);

