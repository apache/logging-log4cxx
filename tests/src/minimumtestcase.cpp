/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/logger.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/ttcclayout.h>
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
#include <apr_pools.h>
#include <apr_strings.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

#define FILTERED LOG4CXX_FILE("output/filtered")

#define TTCC_PAT  \
	ABSOLUTE_DATE_AND_TIME_PAT \
	LOG4CXX_STR(" \\[\\d*]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - Message \\d{1,2}")

#define TTCC2_PAT \
	ABSOLUTE_DATE_AND_TIME_PAT \
	LOG4CXX_STR(" \\[\\d*]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - ") \
	LOG4CXX_STR("Messages should bear numbers 0 through 23\\.")


#define _T(str) L ## str

class MinimumTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(MinimumTestCase);
		CPPUNIT_TEST(simple);
		CPPUNIT_TEST(ttcc);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
		root = Logger::getRootLogger();
		root->removeAllAppenders();
	}

	void tearDown()
	{
		root->getLoggerRepository()->resetConfiguration();
	}

	void simple()
	{
		LayoutPtr layout = new SimpleLayout();
		AppenderPtr appender = new FileAppender(layout, LOG4CXX_FILE("output/simple"), false);
		root->addAppender(appender);
		common();

		CPPUNIT_ASSERT(Compare::compare(LOG4CXX_FILE("output/simple"), LOG4CXX_FILE("witness/simple")));
	}

	void ttcc()
	{
		LayoutPtr layout =
			new TTCCLayout(LOG4CXX_STR("DATE"));
		AppenderPtr appender = new FileAppender(layout, LOG4CXX_FILE("output/ttcc"), false);
		root->addAppender(appender);
		common();

		ControlFilter filter1;
		filter1 << TTCC_PAT << TTCC2_PAT;
		AbsoluteDateAndTimeFilter filter2;
		ThreadFilter filter3;

		std::vector<Filter *> filters;
		filters.push_back(&filter1);
		filters.push_back(&filter2);
		filters.push_back(&filter3);

		try
		{
			Transformer::transform(LOG4CXX_FILE("output/ttcc"), FILTERED, filters);
		}
		catch(std::exception& e)
		{
			std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
			throw;
		}

		CPPUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/ttcc")));
	}

        std::string createMessage(int i, apr_pool_t* p) {
          std::string msg("Message ");
          msg += apr_itoa(p, i);
          return msg;
        }

	void common()
	{
		int i = 0;

		// In the lines below, the category names are chosen as an aid in
		// remembering their level values. In general, the category names
		// have no bearing to level values.
		LoggerPtr ERR = Logger::getLogger(_T("ERR"));
		ERR->setLevel(Level::ERROR);

		LoggerPtr INF = Logger::getLogger(_T("INF"));
		INF->setLevel(Level::INFO);

		LoggerPtr INF_ERR = Logger::getLogger(_T("INF.ERR"));
		INF_ERR->setLevel(Level::ERROR);

		LoggerPtr DEB = Logger::getLogger(_T("DEB"));
		DEB->setLevel(Level::DEBUG);

		// Note: categories with undefined level
		LoggerPtr INF_UNDEF = Logger::getLogger(_T("INF.UNDEF"));
		LoggerPtr INF_ERR_UNDEF = Logger::getLogger(_T("INF.ERR.UNDEF"));
		LoggerPtr UNDEF = Logger::getLogger(_T("UNDEF"));

                apr_pool_t* pool;
                apr_status_t rv = apr_pool_create(&pool, NULL);

                std::string msg("Message ");

		// These should all log.----------------------------
		LOG4CXX_FATAL(ERR, createMessage(i, pool));
		i++; //0
		LOG4CXX_ERROR(ERR, createMessage(i, pool));
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
		LOG4CXX_WARN(ERR, createMessage(i, pool));
		i++;
		LOG4CXX_INFO(ERR, createMessage(i, pool));
		i++;
		LOG4CXX_DEBUG(ERR, createMessage(i, pool));
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
		LOG4CXX_INFO(INF, _T("Messages should bear numbers 0 through 23."));

                apr_pool_destroy(pool);
	}

	LoggerPtr root;
	LoggerPtr logger;
};


CPPUNIT_TEST_SUITE_REGISTRATION(MinimumTestCase);
