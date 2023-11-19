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

#include <log4cxx/net/telnetappender.h>
#include <log4cxx/patternlayout.h>
#include "../appenderskeletontestcase.h"
#include <apr_thread_proc.h>
#include <apr_time.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;

/**
   Unit tests of log4cxx::TelnetAppender
 */
class TelnetAppenderTestCase : public AppenderSkeletonTestCase
{
		LOGUNIT_TEST_SUITE(TelnetAppenderTestCase);
		//
		//    tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);
		LOGUNIT_TEST(testActivateClose);
		LOGUNIT_TEST(testActivateSleepClose);
		LOGUNIT_TEST(testActivateWriteClose);

		LOGUNIT_TEST_SUITE_END();

		enum { TEST_PORT = 1723 };

		static LayoutPtr createLayout()
		{
			PatternLayoutPtr pl = std::make_shared<PatternLayout>();
			pl->setConversionPattern( LOG4CXX_STR("%r [%t] %-5p - %m%n") );
			return pl;
		}

	public:

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new log4cxx::net::TelnetAppender();
		}

		void testActivateClose()
		{
			TelnetAppenderPtr appender(new TelnetAppender());
			appender->setLayout(createLayout());
			appender->setPort(TEST_PORT);
			Pool p;
			appender->activateOptions(p);
			appender->close();
		}

		void testActivateSleepClose()
		{
			TelnetAppenderPtr appender(new TelnetAppender());
			appender->setLayout(createLayout());
			appender->setPort(TEST_PORT);
			Pool p;
			appender->activateOptions(p);
			std::this_thread::sleep_for( std::chrono::milliseconds( 1000 ) );
			appender->close();
		}

		void testActivateWriteClose()
		{
			TelnetAppenderPtr appender(new TelnetAppender());
			appender->setLayout(createLayout());
			appender->setPort(TEST_PORT);
			Pool p;
			appender->activateOptions(p);
			LoggerPtr root(Logger::getRootLogger());
			root->addAppender(appender);

			for (int i = 0; i < 50; i++)
			{
				LOG4CXX_INFO(root, "Hello, World " << i);
			}

			appender->close();
		}

};

LOGUNIT_TEST_SUITE_REGISTRATION(TelnetAppenderTestCase);
