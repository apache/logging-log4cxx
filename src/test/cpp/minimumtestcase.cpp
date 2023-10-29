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
#include <log4cxx/simplelayout.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/helpers/absolutetimedateformat.h>

#include "util/compare.h"
#include "util/transformer.h"
#include "util/linenumberfilter.h"
#include "util/controlfilter.h"
#include "util/absolutedateandtimefilter.h"
#include "util/threadfilter.h"
#include <log4cxx/file.h>
#include <iostream>
#include <log4cxx/helpers/pool.h>
#include <apr_strings.h>
#include "testchar.h"
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/stringhelper.h>
#include <apr_strings.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

LOGUNIT_CLASS(MinimumTestCase)
{
	LOGUNIT_TEST_SUITE(MinimumTestCase);
	LOGUNIT_TEST(simple);
	LOGUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
		root = Logger::getRootLogger();
		root->removeAllAppenders();
	}

	void tearDown()
	{
		auto rep = root->getLoggerRepository();

		if (rep)
		{
			rep->resetConfiguration();
		}
	}

	void simple()
	{
		LayoutPtr layout = LayoutPtr(new SimpleLayout());
		AppenderPtr appender = FileAppenderPtr(new FileAppender(layout, LOG4CXX_STR("output/simple"), false));
		root->addAppender(appender);
		common();

		LOGUNIT_ASSERT(Compare::compare(LOG4CXX_FILE("output/simple"), LOG4CXX_FILE("witness/simple")));
	}

	std::string createMessage(int i, Pool & pool)
	{
		std::string msg("Message ");
		msg.append(pool.itoa(i));
		return msg;
	}

	void common()
	{
		int i = 0;

		// In the lines below, the logger names are chosen as an aid in
		// remembering their level values. In general, the logger names
		// have no bearing to level values.
		LoggerPtr ERRlogger = Logger::getLogger(LOG4CXX_TEST_STR("ERR"));
		ERRlogger->setLevel(Level::getError());

		LoggerPtr INF = Logger::getLogger(LOG4CXX_TEST_STR("INF"));
		INF->setLevel(Level::getInfo());

		LoggerPtr INF_ERR = Logger::getLogger(LOG4CXX_TEST_STR("INF.ERR"));
		INF_ERR->setLevel(Level::getError());

		LoggerPtr DEB = Logger::getLogger(LOG4CXX_TEST_STR("DEB"));
		DEB->setLevel(Level::getDebug());

		// Note: categories with undefined level
		LoggerPtr INF_UNDEF = Logger::getLogger(LOG4CXX_TEST_STR("INF.UNDEF"));
		LoggerPtr INF_ERR_UNDEF = Logger::getLogger(LOG4CXX_TEST_STR("INF.ERR.UNDEF"));
		LoggerPtr UNDEF = Logger::getLogger(LOG4CXX_TEST_STR("UNDEF"));

		std::string msg("Message ");

		Pool pool;

		// These should all log.----------------------------
		LOG4CXX_FATAL(ERRlogger, createMessage(i, pool));
		i++; //0
		LOG4CXX_ERROR(ERRlogger, createMessage(i, pool));
		i++;

		LOG4CXX_FATAL(INF, createMessage(i, pool));
		i++; // 2
		LOG4CXX_ERROR(INF, createMessage(i, pool));
		i++;
		LOG4CXX_WARN(INF, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(INF, createMessage(i, pool));
		i++;

		LOG4CXX_FATAL(INF_UNDEF, createMessage(i, pool));
		i++; //6
		LOG4CXX_ERROR(INF_UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_WARN(INF_UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(INF_UNDEF, createMessage(i, pool));
		i++;

		LOG4CXX_FATAL(INF_ERR, createMessage(i, pool));
		i++; // 10
		LOG4CXX_ERROR(INF_ERR, createMessage(i, pool));
		i++;

		LOG4CXX_FATAL(INF_ERR_UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_ERROR(INF_ERR_UNDEF, createMessage(i, pool));
		i++;

		LOG4CXX_FATAL(DEB, createMessage(i, pool));
		i++; //14
		LOG4CXX_ERROR(DEB, createMessage(i, pool));
		i++;
		LOG4CXX_WARN(DEB, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(DEB, createMessage(i, pool));
		i++;
		LOG4CXX_DEBUG(DEB, createMessage(i, pool));
		i++;

		// defaultLevel=DEBUG
		LOG4CXX_FATAL(UNDEF, createMessage(i, pool));
		i++; // 19
		LOG4CXX_ERROR(UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_WARN(UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_DEBUG(UNDEF, createMessage(i, pool));
		i++;

		// -------------------------------------------------
		// The following should not log
		LOG4CXX_WARN(ERRlogger, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(ERRlogger, createMessage(i, pool));
		i++;
		LOG4CXX_DEBUG(ERRlogger, createMessage(i, pool));
		i++;

		LOG4CXX_DEBUG(INF, createMessage(i, pool));
		i++;
		LOG4CXX_DEBUG(INF_UNDEF, createMessage(i, pool));
		i++;

		LOG4CXX_WARN(INF_ERR, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(INF_ERR, createMessage(i, pool));
		i++;
		LOG4CXX_DEBUG(INF_ERR, createMessage(i, pool));
		i++;
		LOG4CXX_WARN(INF_ERR_UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(INF_ERR_UNDEF, createMessage(i, pool));
		i++;
		LOG4CXX_DEBUG(INF_ERR_UNDEF, createMessage(i, pool));
		i++;

		// -------------------------------------------------
		LOG4CXX_INFO(INF, LOG4CXX_TEST_STR("Messages should bear numbers 0 through 23."));
	}

	LoggerPtr root;
	LoggerPtr logger;

private:
	static const File FILTERED;
};


const File MinimumTestCase::FILTERED("output/minimumfiltered");


LOGUNIT_TEST_SUITE_REGISTRATION(MinimumTestCase);
