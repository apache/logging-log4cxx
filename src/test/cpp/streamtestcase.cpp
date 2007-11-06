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
#include <ostream>
#include <iomanip>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include "vectorappender.h"
#include <log4cxx/logmanager.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/spi/loggingevent.h>
#include "insertwide.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

class ExceptionOnInsert {
public:
   ExceptionOnInsert() {
   }
};

//
//   define an insertion operation that will throw an
//       exception to test that evaluation was short
//       circuited
//
template<class Elem, class Tr>
::std::basic_ostream<Elem, Tr>& operator<<(
   ::std::basic_ostream<Elem, Tr>&,
   const ExceptionOnInsert&) {
   throw std::exception();
}


/**
   Unit tests for the optional stream-like interface for log4cxx
 */
class StreamTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(StreamTestCase);
                CPPUNIT_TEST(testSimple);
                CPPUNIT_TEST(testMultiple);
                CPPUNIT_TEST(testShortCircuit);
                CPPUNIT_TEST_EXCEPTION(testInsertException, std::exception);
                CPPUNIT_TEST(testScientific);
                CPPUNIT_TEST(testPrecision);
                CPPUNIT_TEST(testWidth);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(testWide);
                CPPUNIT_TEST(testWideAppend);
                CPPUNIT_TEST(testWideWidth);
#endif
        CPPUNIT_TEST_SUITE_END();

        VectorAppenderPtr vectorAppender;

public:
        void setUp() {
           LoggerPtr root(Logger::getRootLogger());
           LayoutPtr layout(new SimpleLayout());
           vectorAppender = new VectorAppender();
           root->addAppender(vectorAppender);
        }

        void tearDown()
        {
            LogManager::shutdown();
        }

        void testSimple() {
            LoggerPtr root(Logger::getRootLogger());
            LOG4CXX_INFO(root, "This is a test");
            CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
        }

        void testMultiple() {
           LoggerPtr root(Logger::getRootLogger());
           LOG4CXX_INFO(root, "This is a test" << ": Details to follow");
           CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
       }

       void testShortCircuit() {
         LoggerPtr logger(Logger::getLogger("StreamTestCase.shortCircuit"));
         logger->setLevel(Level::getInfo());
         ExceptionOnInsert someObj;
         LOG4CXX_DEBUG(logger, someObj);
         CPPUNIT_ASSERT_EQUAL((size_t) 0, vectorAppender->getVector().size());
       }

       void testInsertException() {
         LoggerPtr logger(Logger::getLogger("StreamTestCase.insertException"));
         ExceptionOnInsert someObj;
         LOG4CXX_INFO(logger, someObj);
       }

       void testScientific() {
           LoggerPtr root(Logger::getRootLogger());
           LOG4CXX_INFO(root, std::scientific << 0.000001115);
           spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
           LogString msg(event->getMessage());
           CPPUNIT_ASSERT(msg.find(LOG4CXX_STR("e-")) != LogString::npos ||
                msg.find(LOG4CXX_STR("E-")) != LogString::npos);
       }

       void testPrecision() {
          LoggerPtr root(Logger::getRootLogger());
          LOG4CXX_INFO(root, std::setprecision(4) << 1.000001);
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT(msg.find(LOG4CXX_STR("1.00000")) == LogString::npos);
      }


      void testWidth() {
          LoggerPtr root(Logger::getRootLogger());
          LOG4CXX_INFO(root, '[' << std::fixed << std::setprecision(2) << std::setw(7) << std::right << std::setfill('_') << 10.0 << ']');
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("[__10.00]")), msg);
       }

#if LOG4CXX_HAS_WCHAR_T
        void testWide() {
            LoggerPtr root(Logger::getRootLogger());
            LOG4CXX_INFO(root, L"This is a test");
            CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
        }

        void testWideAppend() {
           LoggerPtr root(Logger::getRootLogger());
           LOG4CXX_INFO(root, L"This is a test" << L": Details to follow");
           CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
       }
       
      void testWideWidth() {
          LoggerPtr root(Logger::getRootLogger());
          LOG4CXX_INFO(root, L'[' << std::fixed << std::setprecision(2) << std::setw(7) << std::right << std::setfill(L'_') << 10.0 << L"]");
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("[__10.00]")), msg);
       }
#endif
};

CPPUNIT_TEST_SUITE_REGISTRATION(StreamTestCase);
