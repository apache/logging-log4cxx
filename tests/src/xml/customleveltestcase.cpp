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

#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/file.h>

#include "../util/compare.h"
#include "xlevel.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

#define LOG4CXX_TEST_STR(x) L##x


class CustomLevelTestCase : public CppUnit::TestFixture
{
   CPPUNIT_TEST_SUITE(CustomLevelTestCase);
      CPPUNIT_TEST(test1);
      CPPUNIT_TEST(test2);
      CPPUNIT_TEST(test3);
      CPPUNIT_TEST(test4);
   CPPUNIT_TEST_SUITE_END();

   LoggerPtr root;
   LoggerPtr logger;
    static const File TEMP;

public:
   void setUp()
   {
      root = Logger::getRootLogger();
      logger = Logger::getLogger(LOG4CXX_TEST_STR("xml.CustomLevelTestCase"));
   }

   void tearDown()
   {
      root->getLoggerRepository()->resetConfiguration();

      LoggerPtr logger = Logger::getLogger(LOG4CXX_TEST_STR("LOG4J"));
      logger->setAdditivity(false);
      logger->addAppender(
         new ConsoleAppender(new PatternLayout(LOG4CXX_TEST_STR("log4j: %-22c{2} - %m%n"))));
   }

   void test1()
   {
      DOMConfigurator::configure(LOG4CXX_TEST_STR("input/xml/customLevel1.xml"));
      common();
        const File witness(L"witness/customLevel.1");
      CPPUNIT_ASSERT(Compare::compare(TEMP, witness));
   }

   void test2()
   {
      DOMConfigurator::configure(LOG4CXX_TEST_STR("input/xml/customLevel2.xml"));
      common();
        const File witness(L"witness/customLevel.2");
      CPPUNIT_ASSERT(Compare::compare(TEMP, witness));
   }

   void test3()
   {
      DOMConfigurator::configure(LOG4CXX_TEST_STR("input/xml/customLevel3.xml"));
      common();
        const File witness(L"witness/customLevel.3");
      CPPUNIT_ASSERT(Compare::compare(TEMP, witness));
   }

   void test4()
   {
      DOMConfigurator::configure(LOG4CXX_TEST_STR("input/xml/customLevel4.xml"));
      common();
        const File witness(L"witness/customLevel.4");
      CPPUNIT_ASSERT(Compare::compare(TEMP, witness));
   }

   void common()
   {
      int i = 0;
        std::ostringstream os;
        os << "Message " << ++i;
      LOG4CXX_DEBUG(logger, os.str());
        os.str("");
        os << "Message " <<  ++i;
      LOG4CXX_INFO(logger, os.str());
        os.str("");
        os << "Message " <<  ++i;
      LOG4CXX_WARN(logger, os.str());
        os.str("");
        os << "Message " <<  ++i;
      LOG4CXX_ERROR(logger, os.str());
        os.str("");
        os << "Message " <<  ++i;
      LOG4CXX_LOG(logger, XLevel::TRACE, os.str());
   }
};

CPPUNIT_TEST_SUITE_REGISTRATION(CustomLevelTestCase);

const File CustomLevelTestCase::TEMP(L"output/temp");


#endif //HAVE_XML
