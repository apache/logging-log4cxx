/*
 * Copyright 2003-2005 The Apache Software Foundation.
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

#include <log4cxx/portability.h>

#ifdef HAVE_XML

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>

#include "../util/transformer.h"
#include "../util/compare.h"
#include "../util/controlfilter.h"
#include "../util/threadfilter.h"
#include "../util/linenumberfilter.h"
#include <iostream>
#include <log4cxx/file.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

#define TEST1_A_PAT "FALLBACK - test - Message \\d"
#define TEST1_B_PAT "FALLBACK - root - Message \\d"
#define TEST1_2_PAT \
	"^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3} " \
	"\\[main]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - Message \\d"

class ErrorHandlerTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(ErrorHandlerTestCase);
		CPPUNIT_TEST(test1);
	CPPUNIT_TEST_SUITE_END();

	LoggerPtr root;
	LoggerPtr logger;

    static const File TEMP;
    static const File FILTERED;


public:
	void setUp()
	{
		root = Logger::getRootLogger();
		logger = Logger::getLogger(L"test");
	}

	void tearDown()
	{
		logger->getLoggerRepository()->resetConfiguration();
	}

	void test1()
	{
   		DOMConfigurator::configure("input/xml/fallback1.xml");
		common();
		
		ControlFilter cf;
		cf << TEST1_A_PAT << TEST1_B_PAT << TEST1_2_PAT;
		
		ThreadFilter threadFilter;
		LineNumberFilter lineNumberFilter;

		std::vector<Filter *> filters;
		filters.push_back(&cf);
		filters.push_back(&threadFilter);
		filters.push_back(&lineNumberFilter);

        common();

		try
		{
			Transformer::transform(TEMP, FILTERED, filters);
		}
		catch(UnexpectedFormatException& e)
		{
            std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
			throw;
		}

        const File witness(L"witness/fallback");
		CPPUNIT_ASSERT(Compare::compare(FILTERED, witness));
	}
	
	void common()
	{
		int i = -1;

        std::ostringstream os;
        os << "Message " << ++ i;
		LOG4CXX_DEBUG(logger, os.str());
		LOG4CXX_DEBUG(root, os.str());

        os.str("");
        os << "Message " << ++i;
		LOG4CXX_INFO(logger, os.str());
		LOG4CXX_INFO(root, os.str());

        os.str("");
        os << "Message " << ++i;
		LOG4CXX_WARN(logger, os.str());
		LOG4CXX_WARN(root, os.str());

        os.str("");
        os << "Message " << ++i;
		LOG4CXX_ERROR(logger, os.str());
		LOG4CXX_ERROR(root, os.str());

        os.str("");
        os << "Message " << ++i;
		LOG4CXX_FATAL(logger, os.str());
		LOG4CXX_FATAL(root, os.str());
	}
};

//TODO: Not sure this test ever worked.  0.9.7 didn't call common
//   had nothing that attempted to dispatch any log events

//CPPUNIT_TEST_SUITE_REGISTRATION(ErrorHandlerTestCase);

const File ErrorHandlerTestCase::TEMP(L"output/temp");
const File ErrorHandlerTestCase::FILTERED(L"output/filtered");


#endif //HAVE_XML
