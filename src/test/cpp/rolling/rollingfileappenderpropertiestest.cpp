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


using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::filter;
using namespace log4cxx::helpers;
using namespace log4cxx::rolling;

/**
 *
 */
LOGUNIT_CLASS(RollingFileAppenderPropertiesTest)
{
	LOGUNIT_TEST_SUITE(RollingFileAppenderPropertiesTest);
	LOGUNIT_TEST(testRollingFromProperties);
	LOGUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
	}

	void tearDown()
	{
	}

	void testRollingFromProperties(){
		// Load the properties from the file and make sure that the configured values are
		// what we expect
		PropertyConfigurator::configure(LOG4CXX_FILE("input/rolling/rollingFileAppenderFromProperties.properties"));

		AppenderPtr appender = LogManager::getRootLogger()->getAppender(LOG4CXX_STR("FILE"));
		LOGUNIT_ASSERT(appender);

		RollingFileAppenderPtr rfa = cast<RollingFileAppender>(appender);
		LOGUNIT_ASSERT(rfa);

		FixedWindowRollingPolicyPtr fixedWindowRolling = cast<FixedWindowRollingPolicy>(rfa->getRollingPolicy());
		LOGUNIT_ASSERT(fixedWindowRolling);

		SizeBasedTriggeringPolicyPtr sizeBasedPolicy = cast<SizeBasedTriggeringPolicy>(rfa->getTriggeringPolicy());
		LOGUNIT_ASSERT(sizeBasedPolicy);

		LOGUNIT_ASSERT_EQUAL(3, fixedWindowRolling->getMaxIndex());
		LOGUNIT_ASSERT_EQUAL(100, static_cast<int>(sizeBasedPolicy->getMaxFileSize()));
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(RollingFileAppenderPropertiesTest);
