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
#include <log4cxx/logmanager.h>
#include <log4cxx/simplelayout.h>
#include "vectorappender.h"
#include <log4cxx/asyncappender.h>
#include "appenderskeletontestcase.h"
#include <log4cxx/helpers/pool.h>
#include <apr_strings.h>
#include "testchar.h"
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   A superficial but general test of log4j.
 */
class AsyncAppenderTestCase : public AppenderSkeletonTestCase
{
        CPPUNIT_TEST_SUITE(AsyncAppenderTestCase);
                //
                //    tests inherited from AppenderSkeletonTestCase
                //
                CPPUNIT_TEST(testDefaultThreshold);
                CPPUNIT_TEST(testSetOptionThreshold);

                CPPUNIT_TEST(closeTest);
                CPPUNIT_TEST(test2);
//  TODO: deadlocks on Win32, will debug on Linux
#if !defined(_WIN32)
                CPPUNIT_TEST(test3);
#endif
        CPPUNIT_TEST_SUITE_END();


public:
        void setUp() {
           AppenderSkeletonTestCase::setUp();
        }

        void tearDown()
        {
                LogManager::shutdown();
                AppenderSkeletonTestCase::tearDown();
        }

        AppenderSkeleton* createAppenderSkeleton() const {
          return new AsyncAppender();
        }

        // this test checks whether it is possible to write to a closed AsyncAppender
        void closeTest() throw(Exception)
        {
                LoggerPtr root = Logger::getRootLogger();
                LayoutPtr layout = new SimpleLayout();
                VectorAppenderPtr vectorAppender = new VectorAppender();
                AsyncAppenderPtr asyncAppender = new AsyncAppender();
                asyncAppender->setName(LOG4CXX_STR("async-CloseTest"));
                asyncAppender->addAppender(vectorAppender);
                root->addAppender(asyncAppender);

                root->debug(LOG4CXX_TEST_STR("m1"));
                asyncAppender->close();
                root->debug(LOG4CXX_TEST_STR("m2"));

                const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
                CPPUNIT_ASSERT(v.size() == 1);
        }

        // this test checks whether appenders embedded within an AsyncAppender are also
        // closed
        void test2()
        {
                LoggerPtr root = Logger::getRootLogger();
                LayoutPtr layout = new SimpleLayout();
                VectorAppenderPtr vectorAppender = new VectorAppender();
                AsyncAppenderPtr asyncAppender = new AsyncAppender();
                asyncAppender->setName(LOG4CXX_STR("async-test2"));
                asyncAppender->addAppender(vectorAppender);
                root->addAppender(asyncAppender);

                root->debug(LOG4CXX_TEST_STR("m1"));
                asyncAppender->close();
                root->debug(LOG4CXX_TEST_STR("m2"));

                const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
                CPPUNIT_ASSERT(v.size() == 1);
                CPPUNIT_ASSERT(vectorAppender->isClosed());
        }

        // this test checks whether appenders embedded within an AsyncAppender are also
        // closed
        void test3()
        {
                typedef std::vector<spi::LoggingEventPtr>::size_type size_type;
                size_t LEN = 200;
                LoggerPtr root = Logger::getRootLogger();
                LayoutPtr layout = new SimpleLayout();
                VectorAppenderPtr vectorAppender = new VectorAppender();
                AsyncAppenderPtr asyncAppender = new AsyncAppender();
                asyncAppender->setName(LOG4CXX_STR("async-test3"));
                asyncAppender->addAppender(vectorAppender);
                root->addAppender(asyncAppender);

                Pool pool;
                std::string msg("message");

                for (size_t i = 0; i < LEN; i++) {
                        msg.erase(msg.begin() + 7, msg.end());
                        StringHelper::toString(i, pool, msg);
                        LOG4CXX_DEBUG(root, msg);
                }

                asyncAppender->close();
                root->debug(LOG4CXX_TEST_STR("m2"));

                const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
                CPPUNIT_ASSERT_EQUAL(LEN, v.size());
                CPPUNIT_ASSERT_EQUAL(true, vectorAppender->isClosed());
        }
};

//CPPUNIT_TEST_SUITE_REGISTRATION(AsyncAppenderTestCase);
