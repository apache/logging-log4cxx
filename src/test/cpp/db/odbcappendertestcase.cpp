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

#include <log4cxx/logmanager.h>
#include <log4cxx/db/odbcappender.h>
#include <log4cxx/xml/domconfigurator.h>
#include "../appenderskeletontestcase.h"
#include <apr_time.h>

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>

#ifdef LOG4CXX_HAVE_ODBC

using namespace LOG4CXX_NS;

/**
   Unit tests of log4cxx::SocketAppender
 */
class ODBCAppenderTestCase : public AppenderSkeletonTestCase
{
		LOGUNIT_TEST_SUITE(ODBCAppenderTestCase);
		//
		//	    tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);
		//LOGUNIT_TEST(testConnectUsingDSN);
		LOGUNIT_TEST_SUITE_END();


	public:

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new db::ODBCAppender();
		}

		// Flush the last message to the database prior to process termination
		void tearDown()
		{
			LogManager::shutdown();
		}

// 'odbcAppenderDSN-Log4cxxTest.xml' requires the data souce name 'Log4cxxTest'
// containing a 'ApplicationLogs' database
// with 'UnitTestLog' table
// containing the fields shown below:
//
// USE [ApplicationLogs]
// GO
//
// SET ANSI_NULLS ON
// GO
//
// SET QUOTED_IDENTIFIER ON
// GO
//
// CREATE TABLE [dbo].[UnitTestLog](
//	 [Item] [bigint] IDENTITY(1,1) NOT NULL, /* auto incremented */
//	 [Thread] [nchar](20) NULL
//	 [LogTime] [datetime] NOT NULL,
//	 [LogName] [nchar](50) NULL,
//	 [LogLevel] [nchar](10) NULL,
//	 [FileName] [nchar](300) NULL,
//	 [FileLine] [int] NULL,
//	 [Message] [nchar](1000) NULL
// ) ON [PRIMARY]
// GO
//
		void testConnectUsingDSN()
		{
			xml::DOMConfigurator::configure("input/xml/odbcAppenderDSN-Log4cxxTest.xml");
			auto odbc = Logger::getLogger("DB.UnitTest");
			for (int i = 0; i < 100; ++i)
			{
				LOG4CXX_INFO(odbc, "Message '" << i << "'");
				apr_sleep(30000);
			}
			LOG4CXX_INFO(odbc, "Last message");
		}
};

LOGUNIT_TEST_SUITE_REGISTRATION(ODBCAppenderTestCase);

#endif
