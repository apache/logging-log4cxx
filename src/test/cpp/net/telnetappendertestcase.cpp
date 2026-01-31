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
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/file.h>
#include <log4cxx/patternlayout.h>
#include "../appenderskeletontestcase.h"
#include <log4cxx/helpers/inetaddress.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/spi/configurator.h>
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
		LOGUNIT_TEST(testConnectNoRead);
		LOGUNIT_TEST(testActivateWriteNoClose);

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
			apr_sleep(100000);    // 100 milliseconds
			appender->close();
		}

		void testActivateWriteClose()
		{
			auto internalDebugging = helpers::LogLog::isDebugEnabled();
			if (!internalDebugging)
				helpers::LogLog::setInternalDebugging(true);
			auto appender = std::make_shared<TelnetAppender>();
			appender->setLayout(createLayout());
			appender->setPort(TEST_PORT);
			appender->setReuseAddress(true);
			appender->setNonBlocking(true);
			Pool p;
			appender->activateOptions(p);
			BasicConfigurator::configure(appender);
			auto root = Logger::getRootLogger();

			apr_sleep(200000);    // 200 milliseconds
			for (int i = 0; i < 100000; ++i)
			{
				LOG4CXX_INFO(root, "Hello, World " << i);
			}

			appender->close();
			root->removeAppender(appender);
			if (!internalDebugging)
				helpers::LogLog::setInternalDebugging(false);
		}

		void testActivateWriteNoClose()
		{
			auto appender = std::make_shared<TelnetAppender>();
			appender->setPort(TEST_PORT);
			appender->setMaxConnections(1);
			appender->setReuseAddress(true);
			appender->setHostname(LOG4CXX_STR("127.0.0.1"));
			Pool p;
			appender->activateOptions(p);
			BasicConfigurator::configure(appender);
			auto root = Logger::getRootLogger();

			for (int i = 0; i < 50; i++)
			{
//#define ALLOW_TESTING_WITH_TELNET
#ifdef ALLOW_TESTING_WITH_TELNET
				std::this_thread::sleep_for( std::chrono::milliseconds( 1000 ) );
#endif
				LOG4CXX_INFO(root, "Hello, World " << i);
			}
		}

		void testConnectNoRead()
		{
			auto thisProgram = GetExecutableFileName();
			helpers::Pool p;
			bool thisProgramExists = File(thisProgram).exists(p);
			LOGUNIT_ASSERT(thisProgramExists);
			const char* args[] = {thisProgram.c_str(), "testActivateWriteClose", 0};
			apr_procattr_t* attr = NULL;
			helpers::FileOutputStream output(LOG4CXX_STR("output/testConnectNoRead.log"), false);
			setTestAttributes(&attr, output.getFilePtr(), p);
			apr_proc_t pid;
			startTestInstance(&pid, attr, args, p);
			apr_sleep(100000);    // 100 milliseconds
			auto addr = helpers::InetAddress::getByName(LOG4CXX_STR("127.0.0.1"));
			auto s = helpers::Socket::create(addr, TEST_PORT); // Opens a connection
			int exitCode;
			apr_exit_why_e reason;
			apr_proc_wait(&pid, &exitCode, &reason, APR_WAIT);
			if (exitCode != 0 && helpers::LogLog::isDebugEnabled())
			{
				LogString msg = LOG4CXX_STR("child exit code: ");
				helpers::StringHelper::toString(exitCode, p, msg);
				msg += LOG4CXX_STR("; reason: ");
				helpers::StringHelper::toString(reason, p, msg);
				helpers::LogLog::debug(msg);
			}
			LOGUNIT_ASSERT_EQUAL(exitCode, 0);
		}

private:

	void setTestAttributes(apr_procattr_t** attr, apr_file_t* output, helpers::Pool& p)
	{
		if (apr_procattr_create(attr, p.getAPRPool()) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_create");
		}
		if (apr_procattr_cmdtype_set(*attr, APR_PROGRAM) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_cmdtype_set");
		}
		if (apr_procattr_child_out_set(*attr, output, NULL) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_child_out_set");
		}
		if (apr_procattr_child_err_set(*attr, output, NULL) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_child_err_set");
		}
	}

	void startTestInstance(apr_proc_t* pid, apr_procattr_t* attr, const char** argv, helpers::Pool& p)
	{
		if (apr_proc_create(pid, argv[0], argv, NULL, attr, p.getAPRPool()) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_proc_create");
		}
	}

	std::string GetExecutableFileName()
	{
		auto lsProgramFilePath = spi::Configurator::properties().getProperty(LOG4CXX_STR("PROGRAM_FILE_PATH"));
		LOG4CXX_ENCODE_CHAR(programFilePath, lsProgramFilePath);
		return programFilePath;
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(TelnetAppenderTestCase);
