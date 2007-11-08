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
#include <log4cxx/stream.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace std;

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
                CPPUNIT_TEST(testBaseFlags);
                CPPUNIT_TEST(testBasePrecisionAndWidth);
                CPPUNIT_TEST(testLogStreamSimple);
                CPPUNIT_TEST(testLogStreamMultiple);
                CPPUNIT_TEST(testLogStreamShortCircuit);
                CPPUNIT_TEST_EXCEPTION(testLogStreamInsertException, std::exception);
                CPPUNIT_TEST(testLogStreamScientific);
                CPPUNIT_TEST(testLogStreamPrecision);
                CPPUNIT_TEST(testLogStreamWidth);
                CPPUNIT_TEST(testLogStreamDelegate);
                CPPUNIT_TEST(testLogStreamFormattingPersists);
                CPPUNIT_TEST(testSetWidthInsert);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(testWLogStreamSimple);
                CPPUNIT_TEST(testWLogStreamMultiple);
                CPPUNIT_TEST(testWLogStreamShortCircuit);
                CPPUNIT_TEST_EXCEPTION(testWLogStreamInsertException, std::exception);
                CPPUNIT_TEST(testWLogStreamScientific);
                CPPUNIT_TEST(testWLogStreamPrecision);
                CPPUNIT_TEST(testWLogStreamWidth);
                CPPUNIT_TEST(testWLogStreamDelegate);
                CPPUNIT_TEST(testWLogStreamFormattingPersists);
                CPPUNIT_TEST(testWSetWidthInsert);
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
       void testBaseFlags() {
           logstream base1(Logger::getRootLogger(), Level::getInfo());
           logstream base2(Logger::getRootLogger(), Level::getInfo());
           base1 << std::boolalpha;
           base2 << std::noboolalpha;
           std::ostringstream os1a, os1b, os2a, os2b;
           os1a << std::boolalpha;
           int fillchar;
           if (base1.set_stream_state(os1b, fillchar)) {
               os1b.fill(fillchar);
            }
           CPPUNIT_ASSERT_EQUAL(os1a.flags(), os1b.flags());
           os2a << std::noboolalpha;
           if (base2.set_stream_state(os2b, fillchar)) {
               os2b.fill(fillchar);
            }
           CPPUNIT_ASSERT_EQUAL(os2a.flags(), os2b.flags());
       }


       void testBasePrecisionAndWidth() {
           logstream base(Logger::getRootLogger(), Level::getInfo());
           base.precision(2);
           base.width(5);
           std::ostringstream os1, os2;
           os1.precision(2);
           os1.width(5);
           os1 << 3.1415926;
           int fillchar;
           if (base.set_stream_state(os2, fillchar)) {
               os2.fill(fillchar);
            }
           os2 << 3.1415926;
           string expected(os1.str());
           string actual(os2.str());
           CPPUNIT_ASSERT_EQUAL(expected, actual);
       }
       
        void testLogStreamSimple() {
            logstream root(Logger::getRootLogger(), Level::getInfo());
            root << "This is a test" << LOG4CXX_ENDMSG;
            CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
        }

        void testLogStreamMultiple() {
           logstream root(Logger::getRootLogger(), Level::getInfo());
           root << "This is a test" << ": Details to follow" << LOG4CXX_ENDMSG;
           CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
       }

       void testLogStreamShortCircuit() {
         LoggerPtr logger(Logger::getLogger("StreamTestCase.shortCircuit"));
         logger->setLevel(Level::getInfo());
         logstream os(logger, Level::getDebug());
         ExceptionOnInsert someObj;
         os << someObj << LOG4CXX_ENDMSG;
         CPPUNIT_ASSERT_EQUAL((size_t) 0, vectorAppender->getVector().size());
       }

       void testLogStreamInsertException() {
         LoggerPtr logger(Logger::getLogger("StreamTestCase.insertException"));
         ExceptionOnInsert someObj;
         logstream os(logger, Level::getInfo());
         os << someObj << LOG4CXX_ENDMSG;
       }

       void testLogStreamScientific() {
           LoggerPtr root(Logger::getRootLogger());
           logstream os(root, Level::getInfo());
           os << std::scientific << 0.000001115 << LOG4CXX_ENDMSG;
           spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
           LogString msg(event->getMessage());
           CPPUNIT_ASSERT(msg.find(LOG4CXX_STR("e-")) != LogString::npos ||
                msg.find(LOG4CXX_STR("E-")) != LogString::npos);
       }

       void testLogStreamPrecision() {
          LoggerPtr root(Logger::getRootLogger());
          logstream os(root, Level::getInfo());
          os << std::setprecision(4) << 1.000001 << LOG4CXX_ENDMSG;
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT(msg.find(LOG4CXX_STR("1.00000")) == LogString::npos);
      }


      void testLogStreamWidth() {
          LoggerPtr root(Logger::getRootLogger());
          logstream os(root, Level::getInfo());
          os << '[' << std::fixed << std::setprecision(2) << std::setw(7) << std::right << std::setfill('_') << 10.0 << ']' << LOG4CXX_ENDMSG;
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("[__10.00]")), msg);
       }
       
       void report(std::ostream& os) {
          os << "This just in: \n";
          os << "Use logstream in places that expect a std::ostream.\n";
       }
       
        void testLogStreamDelegate() {
            logstream root(Logger::getRootLogger(), Level::getInfo());
            report(root);
            root << LOG4CXX_ENDMSG;
            CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
        }
        
        void testLogStreamFormattingPersists() {
          LoggerPtr root(Logger::getRootLogger());
          root->setLevel(Level::getInfo());
          logstream os(root, Level::getDebug());
          os << std::hex << 20 << LOG4CXX_ENDMSG;
          os << Level::getInfo() << 16 << LOG4CXX_ENDMSG;
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("10")), msg);
        }

        void testSetWidthInsert() {
          LoggerPtr root(Logger::getRootLogger());
          root->setLevel(Level::getInfo());
          logstream os(root, Level::getInfo());
          os << std::setw(5);
          CPPUNIT_ASSERT_EQUAL(5, os.width());
        }
        
        

#if LOG4CXX_HAS_WCHAR_T
        void testWLogStreamSimple() {
            wlogstream root(Logger::getRootLogger(), Level::getInfo());
            root << L"This is a test" << LOG4CXX_ENDMSG;
            CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
        }

        void testWLogStreamMultiple() {
           wlogstream root(Logger::getRootLogger(), Level::getInfo());
           root << L"This is a test" << L": Details to follow" << LOG4CXX_ENDMSG;
           CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
       }

       void testWLogStreamShortCircuit() {
         LoggerPtr logger(Logger::getLogger("StreamTestCase.shortCircuit"));
         logger->setLevel(Level::getInfo());
         wlogstream os(logger, Level::getDebug());
         ExceptionOnInsert someObj;
         os << someObj << LOG4CXX_ENDMSG;
         CPPUNIT_ASSERT_EQUAL((size_t) 0, vectorAppender->getVector().size());
       }

       void testWLogStreamInsertException() {
         LoggerPtr logger(Logger::getLogger("StreamTestCase.insertException"));
         ExceptionOnInsert someObj;
         wlogstream os(logger, Level::getInfo());
         os << someObj << LOG4CXX_ENDMSG;
       }

       void testWLogStreamScientific() {
           LoggerPtr root(Logger::getRootLogger());
           wlogstream os(root, Level::getInfo());
           os << std::scientific << 0.000001115 << LOG4CXX_ENDMSG;
           spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
           LogString msg(event->getMessage());
           CPPUNIT_ASSERT(msg.find(LOG4CXX_STR("e-")) != LogString::npos ||
                msg.find(LOG4CXX_STR("E-")) != LogString::npos);
       }

       void testWLogStreamPrecision() {
          LoggerPtr root(Logger::getRootLogger());
          wlogstream os(root, Level::getInfo());
          os << std::setprecision(4) << 1.000001 << LOG4CXX_ENDMSG;
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT(msg.find(LOG4CXX_STR("1.00000")) == LogString::npos);
      }


      void testWLogStreamWidth() {
          LoggerPtr root(Logger::getRootLogger());
          wlogstream os(root, Level::getInfo());
          os << L"[" << std::fixed << std::setprecision(2) << std::setw(7) << std::right << std::setfill(L'_') << 10.0 << L"]" << LOG4CXX_ENDMSG;
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("[__10.00]")), msg);
       }
       
       void wreport(std::wostream& os) {
          os << L"This just in: \n";
          os << L"Use logstream in places that expect a std::ostream.\n";
       }
       
        void testWLogStreamDelegate() {
            wlogstream root(Logger::getRootLogger(), Level::getInfo());
            wreport(root);
            root << LOG4CXX_ENDMSG;
            CPPUNIT_ASSERT_EQUAL((size_t) 1, vectorAppender->getVector().size());
        }
        
        void testWLogStreamFormattingPersists() {
          LoggerPtr root(Logger::getRootLogger());
          root->setLevel(Level::getInfo());
          wlogstream os(root, Level::getDebug());
          os << std::hex << 20 << LOG4CXX_ENDMSG;
          os << Level::getInfo() << 16 << LOG4CXX_ENDMSG;
          spi::LoggingEventPtr event(vectorAppender->getVector()[0]);
          LogString msg(event->getMessage());
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("10")), msg);
        }

        void testWSetWidthInsert() {
          LoggerPtr root(Logger::getRootLogger());
          root->setLevel(Level::getInfo());
          wlogstream os(root, Level::getInfo());
          os << std::setw(5);
          CPPUNIT_ASSERT_EQUAL(5, os.width());
        }
        
#endif        

};

CPPUNIT_TEST_SUITE_REGISTRATION(StreamTestCase);
