
/*
 * Copyright 2005 The Apache Software Foundation.
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

#include <log4cxx/ndc.h>
#include <log4cxx/file.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include "insertwide.h"
#include "util/compare.h"



using namespace log4cxx;

class NDCTestCase : public CppUnit::TestFixture
{
         static File TEMP;
         static LoggerPtr logger;

        CPPUNIT_TEST_SUITE(NDCTestCase);
                CPPUNIT_TEST(testPushPop);
                CPPUNIT_TEST(test1);
        CPPUNIT_TEST_SUITE_END();

public:

        void setUp() {
        }

        void tearDown() {
            logger->getLoggerRepository()->resetConfiguration();
        }

        /**
         *   Push and pop a value from the NDC
         */
        void testPushPop()
        {
                NDC::push("trivial context");
                LogString actual(NDC::pop());
                CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("trivial context"), actual);
        }


        void test1()  {
            PropertyConfigurator::configure(File("input/ndc/NDC1.properties"));
            common();
            CPPUNIT_ASSERT(Compare::compare(TEMP, File("witness/ndc/NDC.1")));
        }

        static void common() {
            commonLog();
            NDC::push("n1");
            commonLog();
            NDC::push("n2");
            NDC::push("n3");
            commonLog();
            NDC::pop();
            commonLog();
            NDC::clear();
            commonLog();
        }

        static void commonLog() {
            LOG4CXX_DEBUG(logger, "m1");
            LOG4CXX_INFO(logger, "m2");
            LOG4CXX_WARN(logger, "m3");
            LOG4CXX_ERROR(logger, "m4");
            LOG4CXX_FATAL(logger, "m5");
        }

};


File NDCTestCase::TEMP("output/temp");
LoggerPtr NDCTestCase::logger(Logger::getLogger("org.apache.log4j.NDCTestCase"));

CPPUNIT_TEST_SUITE_REGISTRATION(NDCTestCase);
