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

#ifdef LOG4CXX_HAVE_XML

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include "xlogger.h"
#include <log4cxx/xml/domconfigurator.h>
#include "../util/transformer.h"
#include "../util/compare.h"
#include <log4cxx/file.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

#define LOG4CXX_TEST_STR(x) L##x

/**
   Tests handling of custom loggers.
*/
class XLoggerTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(XLoggerTestCase);
		CPPUNIT_TEST(test1);
		CPPUNIT_TEST(test2);
	CPPUNIT_TEST_SUITE_END();

	XLoggerPtr logger;

public:
	void setUp()
	{
		logger =
			(XLoggerPtr) XLogger::getLogger(
			LOG4CXX_TEST_STR("org.apache.log4j.customLogger.XLoggerTestCase"));
	}

	void tearDown()
	{
		logger->getLoggerRepository()->resetConfiguration();
	}

	void test1() { common(LOG4CXX_TEST_STR("1")); }
	void test2() { common(LOG4CXX_TEST_STR("2")); }

	void common(const LogString& number)
	{
        DOMConfigurator::configure(LOG4CXX_TEST_STR("input/xml/customLogger")
			+number+LOG4CXX_TEST_STR(".xml"));
		
		int i = -1;
        std::ostringstream os;
        os << "Message " << ++i;
        if (logger->isEnabledFor(log4cxx::XLevel::TRACE)) {
           logger->forcedLog(log4cxx::XLevel::TRACE, os.str(), LOG4CXX_LOCATION); 
        }

        os.str("");
        os << "Message " << ++ i;
		LOG4CXX_DEBUG(logger, os.str());
        os.str("");
        os << "Message " << ++ i;
		LOG4CXX_WARN(logger, os.str());
        os.str("");
        os << "Message " << ++ i;
		LOG4CXX_ERROR(logger, os.str());
        os.str("");
        os << "Message " << ++ i;
		LOG4CXX_FATAL(logger, os.str());
        os.str("");
        os << "Message " << ++ i;
		LOG4CXX_DEBUG(logger, os.str());

        const File OUTPUT(L"output/temp");
        const File WITNESS(LogString(LOG4CXX_STR("witness/customLogger.")) + number);
		CPPUNIT_ASSERT(Compare::compare(OUTPUT, WITNESS));
//#endif
    }
};

CPPUNIT_TEST_SUITE_REGISTRATION(XLoggerTestCase);

#endif //HAVE_XML
