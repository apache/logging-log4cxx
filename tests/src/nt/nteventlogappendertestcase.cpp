/*
 * Copyright 2004 The Apache Software Foundation.
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

#if defined(_WIN32)
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/nt/nteventlogappender.h>
#include "../appenderskeletontestcase.h"
#include <apr_time.h>
#include "windows.h"
#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/patternlayout.h>
#include "../insertwide.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::nt;
using namespace log4cxx::spi;

/**
   Unit tests of log4cxx::nt::NTEventLogAppender
 */
class NTEventLogAppenderTestCase : public AppenderSkeletonTestCase
{
   CPPUNIT_TEST_SUITE(NTEventLogAppenderTestCase);
                //
                //    tests inherited from AppenderSkeletonTestCase
                //
                CPPUNIT_TEST(testDefaultThreshold);
                CPPUNIT_TEST(testSetOptionThreshold);
                CPPUNIT_TEST(testHelloWorld);

   CPPUNIT_TEST_SUITE_END();


public:

        AppenderSkeleton* createAppenderSkeleton() const {
          return new log4cxx::nt::NTEventLogAppender();
        }

        void testHelloWorld() {
           DWORD expectedId = 1;
           HANDLE hEventLog = ::OpenEventLogW(NULL, L"log4cxx_test");
           if (hEventLog != NULL) {
               BOOL stat = GetNumberOfEventLogRecords(hEventLog, &expectedId);
               DWORD oldest;
               if(stat) stat = GetOldestEventLogRecord(hEventLog, &oldest);
               CloseEventLog(hEventLog);
               CPPUNIT_ASSERT(stat);
               expectedId += oldest;
           }
 

            Pool p;
            DWORD expectedTime = apr_time_sec(apr_time_now());
            {
                NTEventLogAppenderPtr appender(new NTEventLogAppender());
                appender->setSource(LOG4CXX_STR("log4cxx_test"));
                LayoutPtr layout(new PatternLayout(LOG4CXX_STR("%c - %m%n")));
                appender->setLayout(layout);
                appender->activateOptions(p);
                LoggerPtr logger(Logger::getLogger(L"org.foobar"));

                LoggingEventPtr event(new LoggingEvent(
                    logger, Level::INFO, LOG4CXX_STR("Hello,  World"), LOG4CXX_LOCATION));
                appender->doAppend(event, p);
            }
            hEventLog = ::OpenEventLogW(NULL, L"log4cxx_test");
            CPPUNIT_ASSERT(hEventLog != NULL);
            DWORD actualId;
            BOOL stat = GetNumberOfEventLogRecords(hEventLog, &actualId);
            DWORD oldest;
            if (stat) stat = GetOldestEventLogRecord(hEventLog, &oldest);
            actualId += oldest;
            actualId--;
            CloseEventLog(hEventLog);
            CPPUNIT_ASSERT(stat);
            CPPUNIT_ASSERT_EQUAL(expectedId, actualId);
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION(NTEventLogAppenderTestCase);
#endif
