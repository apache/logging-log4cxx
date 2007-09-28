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
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/file.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

class NullPointerAppender : public AppenderSkeleton {
public:
    NullPointerAppender() {
    }


    /**
     * @{inheritDoc}
     */
    void append(const spi::LoggingEventPtr&, log4cxx::helpers::Pool&) {
         throw NullPointerException("Intentional NullPointerException");
    }

    void close() {
    }

    bool requiresLayout() const {
            return false;
    }
};

    /**
     * Vector appender that can be explicitly blocked.
     */
class BlockableVectorAppender : public VectorAppender {
private:
      Mutex blocker;
public:
      /**
       * Create new instance.
       */
      BlockableVectorAppender() : blocker(pool) {
      }

      /**
       * {@inheritDoc}
       */
    void append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p) {
          synchronized sync(blocker);
          VectorAppender::append(event, p);
            //
            //   if fatal, echo messages for testLoggingInDispatcher
            //
            if (event->getLevel() == Level::getInfo()) {
                LoggerPtr logger = Logger::getLogger(event->getLoggerName());
                LOG4CXX_ERROR(logger, event->getMessage());
                LOG4CXX_WARN(logger, event->getMessage());
                LOG4CXX_INFO(logger, event->getMessage());
                LOG4CXX_DEBUG(logger, event->getMessage());
            }
      }
      
      Mutex& getBlocker() {
          return blocker;
      }

    };

typedef helpers::ObjectPtrT<BlockableVectorAppender> BlockableVectorAppenderPtr;


/**
 * Tests of AsyncAppender.
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
                CPPUNIT_TEST(test3);
                //
                //   TODO: test fails on Linux.
                //CPPUNIT_TEST(testBadAppender);
                CPPUNIT_TEST(testLocationInfoTrue);
                CPPUNIT_TEST(testConfiguration);
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
        void closeTest() 
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
                CPPUNIT_ASSERT_EQUAL((size_t) 1, v.size());
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
                CPPUNIT_ASSERT_EQUAL((size_t) 1, v.size());
                CPPUNIT_ASSERT(vectorAppender->isClosed());
        }

        // this test checks whether appenders embedded within an AsyncAppender are also
        // closed
        void test3()
        {
                size_t LEN = 200;
                LoggerPtr root = Logger::getRootLogger();
                VectorAppenderPtr vectorAppender = new VectorAppender();
                AsyncAppenderPtr asyncAppender = new AsyncAppender();
                asyncAppender->setName(LOG4CXX_STR("async-test3"));
                asyncAppender->addAppender(vectorAppender);
                root->addAppender(asyncAppender);

                for (size_t i = 0; i < LEN; i++) {
                        LOG4CXX_DEBUG(root, "message" << i);
                }

                asyncAppender->close();
                root->debug(LOG4CXX_TEST_STR("m2"));

                const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
                CPPUNIT_ASSERT_EQUAL(LEN, v.size());
                CPPUNIT_ASSERT_EQUAL(true, vectorAppender->isClosed());
        }
        
    /**
     * Tests that a bad appender will switch async back to sync.
     */
    void testBadAppender() {
        AppenderPtr nullPointerAppender = new NullPointerAppender();
        AsyncAppenderPtr asyncAppender = new AsyncAppender();
        asyncAppender->addAppender(nullPointerAppender);
        asyncAppender->setBufferSize(5);
        Pool p;
        asyncAppender->activateOptions(p);
        LoggerPtr root = Logger::getRootLogger();
        root->addAppender(asyncAppender);
        LOG4CXX_INFO(root, "Message");
        Thread::sleep(10);
        try {
           LOG4CXX_INFO(root, "Message");
           CPPUNIT_FAIL("Should have thrown exception");
        } catch(NullPointerException& ex) {
        }
    }
    
    /**
     * Tests non-blocking behavior.
     */
    void testLocationInfoTrue() {
        BlockableVectorAppenderPtr blockableAppender = new BlockableVectorAppender();
        AsyncAppenderPtr async = new AsyncAppender();
        async->addAppender(blockableAppender);
        async->setBufferSize(5);
        async->setLocationInfo(true);
        async->setBlocking(false);
        Pool p;
        async->activateOptions(p);
        LoggerPtr rootLogger = Logger::getRootLogger();
        rootLogger->addAppender(async);
        {
            synchronized sync(blockableAppender->getBlocker());
            for (int i = 0; i < 100; i++) {
                   LOG4CXX_INFO(rootLogger, "Hello, World");
                   Thread::sleep(1);
            }
            LOG4CXX_ERROR(rootLogger, "That's all folks.");
        }
        async->close();
        const std::vector<spi::LoggingEventPtr>& events = blockableAppender->getVector();
        LoggingEventPtr initialEvent = events[0];
        LoggingEventPtr discardEvent = events[events.size() - 1];
        CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Hello, World")), initialEvent->getMessage());
        CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Discarded ")), discardEvent->getMessage().substr(0,10));
        CPPUNIT_ASSERT_EQUAL(log4cxx::spi::LocationInfo::getLocationUnavailable().getClassName(), 
            discardEvent->getLocationInformation().getClassName()); 
    }
    
        void testConfiguration() {
              log4cxx::xml::DOMConfigurator::configure("input/xml/asyncAppender1.xml");
              AsyncAppenderPtr asyncAppender(Logger::getRootLogger()->getAppender(LOG4CXX_STR("ASYNC")));
              CPPUNIT_ASSERT(0 != asyncAppender);
              CPPUNIT_ASSERT_EQUAL(100, asyncAppender->getBufferSize());
              CPPUNIT_ASSERT_EQUAL(false, asyncAppender->getBlocking());
              CPPUNIT_ASSERT_EQUAL(true, asyncAppender->getLocationInfo());
              AppenderList nestedAppenders(asyncAppender->getAllAppenders());
              //   TODO:
              //   test seems to work okay, but have not found a working way to 
              //      get a reference to the nested vector appender 
              //
//              CPPUNIT_ASSERT_EQUAL((size_t) 1, nestedAppenders.size());
//              VectorAppenderPtr vectorAppender(nestedAppenders[0]);
//              CPPUNIT_ASSERT(0 != vectorAppender);
              LoggerPtr root(Logger::getRootLogger()); 
              
              size_t LEN = 20;
              for (size_t i = 0; i < LEN; i++) {
                        LOG4CXX_DEBUG(root, "message" << i);
              }
              
              asyncAppender->close();
//              const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
//              CPPUNIT_ASSERT_EQUAL(LEN, v.size());
//              CPPUNIT_ASSERT_EQUAL(true, vectorAppender->isClosed());
        }

        
};

CPPUNIT_TEST_SUITE_REGISTRATION(AsyncAppenderTestCase);
