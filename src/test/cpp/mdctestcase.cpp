
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

#include <log4cxx/mdc.h>
#include <log4cxx/file.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include "insertwide.h"
#include "logunit.h"
#include "util/compare.h"



using namespace log4cxx;

LOGUNIT_CLASS(MDCTestCase)
{
	LOGUNIT_TEST_SUITE(MDCTestCase);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST_SUITE_END();

public:

	void setUp()
	{
	}

	void tearDown()
	{
		Logger::getRootLogger()->getLoggerRepository()->resetConfiguration();
	}

	/**
	 *   log4cxx 0.10.0 did not replace previously set value.
	 */
	void test1()
	{
		std::string key("key1");
		std::string expected("value2");
		MDC::put(key, "value1");
		MDC::put(key, expected);
		std::string actual(MDC::get(key));
		LOGUNIT_ASSERT_EQUAL(expected, actual);
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(MDCTestCase);
