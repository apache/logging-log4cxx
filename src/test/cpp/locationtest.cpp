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

#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>

#include "testchar.h"
#include "logunit.h"
#include "util/compare.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

LOGUNIT_CLASS(LocationTest)
{
	LOGUNIT_TEST_SUITE(LocationTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST_SUITE_END();

	LoggerPtr root;
	LoggerPtr logger;

public:
	void setUp()
	{
		root = Logger::getRootLogger();
	}

	void tearDown()
	{
		if (auto rep = root->getLoggerRepository())
			rep->resetConfiguration();
	}

	void test1()
	{
		PropertyConfigurator::configure(LOG4CXX_FILE("input/location1.properties"));
		common();
		LOGUNIT_ASSERT(Compare::compare(LOG4CXX_STR("output/location-good-test"), LOG4CXX_FILE("witness/location1-good")));
	}

	std::string createMessage(Pool & pool, int i)
	{
		std::string msg("Message ");
		msg.append(pool.itoa(i));
		return msg;
	}

	void common()
	{
		int i = -1;

		Pool pool;

		LOG4CXX_DEBUG(root, createMessage(pool, i));
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(LocationTest);
