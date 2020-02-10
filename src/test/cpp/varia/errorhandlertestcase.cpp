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
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/varia/fallbackerrorhandler.h>
#include "../logunit.h"
#include "../util/transformer.h"
#include "../util/compare.h"
#include "../util/controlfilter.h"
#include "../util/linenumberfilter.h"
#include <iostream>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

LOGUNIT_CLASS(ErrorHandlerTestCase)
{
	LOGUNIT_TEST_SUITE(ErrorHandlerTestCase);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST_SUITE_END();

	LoggerPtr root;
	LoggerPtr logger;


public:
	void setUp()
	{
		root = Logger::getRootLogger();
		logger = Logger::getLogger("test");
	}

	void tearDown()
	{
		logger->getLoggerRepository()->resetConfiguration();
	}


	void test1()
	{
		DOMConfigurator::configure("input/xml/fallback1.xml");
		FileAppenderPtr primary(root->getAppender(LOG4CXX_STR("PRIMARY")));
		log4cxx::varia::FallbackErrorHandlerPtr eh(primary->getErrorHandler());
		LOGUNIT_ASSERT(eh != 0);

		common();

		std::string TEST1_PAT =
			"FALLBACK - (root|test) - Message {0-9}";

		ControlFilter cf;
		cf << TEST1_PAT;

		LineNumberFilter lineNumberFilter;

		std::vector<Filter*> filters;
		filters.push_back(&cf);
		filters.push_back(&lineNumberFilter);

		try
		{
			Transformer::transform("output/temp", "output/filtered", filters);
		}
		catch (UnexpectedFormatException& e)
		{
			std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
			throw;
		}


		LOGUNIT_ASSERT(Compare::compare("output/filtered", "witness/fallback1"));
	}

	void common()
	{
		int i = -1;

		LOG4CXX_DEBUG(logger, "Message " << ++i);
		LOG4CXX_DEBUG(root, "Message " << i);

		LOG4CXX_INFO(logger, "Message " << ++i);
		LOG4CXX_INFO(root, "Message " << i);

		LOG4CXX_WARN(logger, "Message " << ++i);
		LOG4CXX_WARN(root, "Message " << i);

		LOG4CXX_ERROR(logger, "Message " << ++i);
		LOG4CXX_ERROR(root, "Message " << i);

		LOG4CXX_FATAL(logger, "Message " << ++i);
		LOG4CXX_FATAL(root, "Message " << i);

		LOG4CXX_DEBUG(logger, "Message " << ++i);
		LOG4CXX_DEBUG(root, "Message " << i);

		LOG4CXX_ERROR(logger, "Message " << ++i);
		LOG4CXX_ERROR(root, "Message " << i);
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(ErrorHandlerTestCase)
