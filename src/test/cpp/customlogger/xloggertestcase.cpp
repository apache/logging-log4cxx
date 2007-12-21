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

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>


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
      logger = XLogger::getLogger(
            LOG4CXX_STR("org.apache.log4j.customLogger.XLoggerTestCase"));
   }

   void tearDown()
   {
      logger->getLoggerRepository()->resetConfiguration();
   }

   void test1() { common("1"); }
   void test2() { common("2"); }

   void common(const char* number)
   {
        std::string fn("input/xml/customLogger");
        fn.append(number);
        fn.append(".xml");
        DOMConfigurator::configure(fn);

        int i = -1;
        std::ostringstream os;
        os << "Message " << ++i;
        if (logger->isEnabledFor(log4cxx::XLevel::getTrace())) {
           logger->forcedLog(log4cxx::XLevel::getTrace(), os.str(), LOG4CXX_LOCATION);
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

        const File OUTPUT("output/temp");
        std::string witness("witness/customLogger.");
        witness.append(number);
        const File WITNESS(witness);
      CPPUNIT_ASSERT(Compare::compare(OUTPUT, WITNESS));
//#endif
    }
};

CPPUNIT_TEST_SUITE_REGISTRATION(XLoggerTestCase);

