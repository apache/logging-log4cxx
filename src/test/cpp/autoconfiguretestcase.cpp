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
#include <log4cxx/logmanager.h>
#include <log4cxx/file.h>
#include "util/compare.h"

using namespace log4cxx;
LOGUNIT_CLASS(AutoConfigureTestCase)
{
	LOGUNIT_TEST_SUITE(AutoConfigureTestCase);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST_SUITE_END();

public:

	void test1()
	{
		LoggerPtr debugLogger = Logger::getLogger(LOG4CXX_STR("AutoConfig.test1"));
		LOGUNIT_ASSERT(!debugLogger->isDebugEnabled());
		LOGUNIT_ASSERT(LogManager::getLoggerRepository()->isConfigured());
    }

	void test2()
	{
		LoggerPtr debugLogger = Logger::getLogger(LOG4CXX_STR("AutoConfig.test2"));
		LOGUNIT_ASSERT(debugLogger->isDebugEnabled());
		LOG4CXX_DEBUG(debugLogger, LOG4CXX_STR("This is some expected ouput"));
		LOGUNIT_ASSERT_EQUAL(true, Compare::compare
				( File("output/autoConfigureTest.log")
				, File("witness/autoConfigureTest.log")
				));
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(AutoConfigureTestCase);
