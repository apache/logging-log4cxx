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

#include <log4cxx/net/jsonsocketappender.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/logmanager.h>
#include "../appenderskeletontestcase.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   Unit tests of log4cxx::net::JSONSocketAppender
 */
class JSONSocketAppenderTestCase : public AppenderSkeletonTestCase
{
		LOGUNIT_TEST_SUITE(JSONSocketAppenderTestCase);
		//
		//    tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);
		LOGUNIT_TEST(test_fluent_bit);

		LOGUNIT_TEST_SUITE_END();


	public:
		void tearDown() override
		{
			LogManager::shutdown();
		}

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new log4cxx::net::JSONSocketAppender();
		}

		void test_fluent_bit()
		{
			auto status = xml::DOMConfigurator::configure("input/xml/fluent-bit.xml");
			LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
			auto log = Logger::getRootLogger();
			for (int i = 0; i < 100; ++i)
			{
				LOG4CXX_INFO(log, "Message '" << i << "'");
			}
			LOG4CXX_INFO(log, "Last message");
		}
};

LOGUNIT_TEST_SUITE_REGISTRATION(JSONSocketAppenderTestCase);

