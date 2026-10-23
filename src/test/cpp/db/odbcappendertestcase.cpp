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
#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/system.h>
#include "../appenderskeletontestcase.h"
#include <apr_time.h>
#include <fstream>

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>

#ifdef LOG4CXX_HAVE_ODBC

using namespace log4cxx;

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
		LOGUNIT_TEST(testNegativeBufferSizeOption);
		LOGUNIT_TEST(testConnectUsingDSN);
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

		void testNegativeBufferSizeOption()
		{
			db::ODBCAppender appender;
			appender.setOption(LOG4CXX_STR("BUFFERSIZE"), LOG4CXX_STR("-10"));
			LOGUNIT_ASSERT_EQUAL((size_t) 1, appender.getBufferSize());
		}

// testConnectUsingDSN requires the environment variable LOG4CXX_ODBC_TEST_DATA_FILE_PATH
// that names a properties file that has entries specifiing
// the data souce name (e.g. Log4cxxTest) identifying a database
// and a table name (e.g. UnitTestLog )
// where the table contains the fields shown
// in the following SQL data definition language statements:
// SQLite:
// CREATE TABLE UnitTestLog(
//     Item INTEGER PRIMARY KEY AUTOINCREMENT,
//     Thread VARCHAR(20),
//     LogTime DATETIME NOT NULL,
//     LogName VARCHAR(50),
//     LogLevel VARCHAR(10),
//     FileName VARCHAR(300),
//     FileLine INTEGER,
//     Message VARCHAR(1000)
// );
//
// MSSQLServer:
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
//	 [Thread] [nchar](20) NULL,
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
			LogString odbcDataFileNameVar = LOG4CXX_STR("LOG4CXX_ODBC_TEST_DATA_FILE_PATH");
			auto odbcDataFileName = helpers::System::getProperty(odbcDataFileNameVar);
			if (odbcDataFileName.empty())
			{
				helpers::LogLog::warn(
					LOG4CXX_STR("Set the ") + odbcDataFileNameVar + LOG4CXX_STR(" environment variable"
					" and re-run testConnectUsingDSN to initialise it with the required values")
					);
				return;
			}
			File odbcDataFile(odbcDataFileName);
			if (!odbcDataFile.exists())
			{
				std::ofstream f(odbcDataFileName);
				const char odbcData[] =
					"LOG4CXX_TEST_ODBC_DSN=\n"
					"LOG4CXX_TEST_ODBC_TABLE_NAME=\n"
					;
				f.write(odbcData, sizeof (odbcData));
				f.close();
				LOGUNIT_ASSERT(odbcDataFile.exists());
				helpers::LogLog::warn(LOG4CXX_STR("Edit values into '") + odbcDataFileName + LOG4CXX_STR("' and re-run testConnectUsingDSN"));
				return;
			}
			auto odbcDataStream = std::make_shared<helpers::FileInputStream>(odbcDataFile);
			helpers::Properties& odbcData = spi::Configurator::properties();
			odbcData.load(odbcDataStream);
			LOGUNIT_ASSERT(!odbcData.getProperty(LOG4CXX_STR("LOG4CXX_TEST_ODBC_DSN")).empty());
			LOGUNIT_ASSERT(!odbcData.getProperty(LOG4CXX_STR("LOG4CXX_TEST_ODBC_TABLE_NAME")).empty());
			auto status = xml::DOMConfigurator::configure("input/xml/odbcAppenderDSN-Log4cxxTest.xml");
			LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
			auto odbc = Logger::getLogger("DB.UnitTest");
			for (int i = 0; i < 100; ++i)
			{
				LOG4CXX_INFO(odbc, "Message '" << i << "'");
				apr_sleep(30000); // 30 milliseconds
			}
			LOG4CXX_INFO(odbc, "Last message");
		}
};

LOGUNIT_TEST_SUITE_REGISTRATION(ODBCAppenderTestCase);

#endif
