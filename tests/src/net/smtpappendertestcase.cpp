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

#if LOG4CXX_HAVE_SMTP

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/net/smtpappender.h>
#include "../appenderskeletontestcase.h"

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>


using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   Unit tests of log4cxx::SocketAppender
 */
class SMTPAppenderTestCase : public AppenderSkeletonTestCase
{
   CPPUNIT_TEST_SUITE(SMTPAppenderTestCase);
                //
                //    tests inherited from AppenderSkeletonTestCase
                //
                CPPUNIT_TEST(testDefaultThreshold);
                CPPUNIT_TEST(testSetOptionThreshold);

   CPPUNIT_TEST_SUITE_END();


public:

        AppenderSkeleton* createAppenderSkeleton() const {
          return new log4cxx::net::SMTPAppender();
        }
};

CPPUNIT_TEST_SUITE_REGISTRATION(SMTPAppenderTestCase);

#endif
