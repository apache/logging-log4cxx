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

#include "../util/compare.h"
#include "../logunit.h"
#include "../insertwide.h"
#include <log4cxx/logmanager.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/rolling/multiprocessrollingfileappender.h>
#include <log4cxx/rolling/sizebasedtriggeringpolicy.h>
#include <log4cxx/helpers/strftimedateformat.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <filesystem>
#include <fstream>
#include <apr_thread_proc.h>

using namespace LOG4CXX_NS;

auto getLogger(const std::string& name) -> LoggerPtr {
	static struct log4cxx_initializer {
		log4cxx_initializer() {
			xml::DOMConfigurator::configure("input/rolling/multiprocess.xml");
		}
		~log4cxx_initializer() {
			LogManager::shutdown();
		}
	} initAndShutdown;
	return name.empty()
		? LogManager::getRootLogger()
		: LogManager::getLogger(name);
}

LOGUNIT_CLASS(MultiprocessRollingTest)
{
	LOGUNIT_TEST_SUITE(MultiprocessRollingTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST_SUITE_END();

public:
	/**
	 * Test a numeric rolling policy with a log level based trigger.
	 */
	void test1()
	{
		auto logger = getLogger(LOG4CXX_STR("Test1"));
		for (int i = 0; i < 25; i++)
		{
			char msg[10];
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_SECURE_LIB__)
			strcpy_s(msg, sizeof msg, "Hello---?");
#else
			strcpy(msg, "Hello---?");
#endif

			if (i < 10)
			{
				msg[8] = (char) ('0' + i);
				LOG4CXX_DEBUG(logger, msg);
			}
			else if (i < 100)
			{
				msg[7] = (char) ('0' + (i / 10));
				msg[8] = (char) ('0' + (i % 10));

				if ((i % 10) == 0)
				{
					LOG4CXX_WARN(logger, msg);
				}
				else
				{
					LOG4CXX_DEBUG(logger, msg);
				}
			}
		}

		LogString baseName = LOG4CXX_STR("output/rolling/multiprocess-test");
		LOGUNIT_ASSERT_EQUAL(true,
			Compare::compare(baseName + LOG4CXX_STR(".log"), LogString(LOG4CXX_STR("witness/rolling/multiprocess-test.log"))));
		LOGUNIT_ASSERT_EQUAL(true,
			Compare::compare(baseName + LOG4CXX_STR(".0"), LogString(LOG4CXX_STR("witness/rolling/multiprocess-test.0"))));
		LOGUNIT_ASSERT_EQUAL(true,
			Compare::compare(baseName + LOG4CXX_STR(".1"), LogString(LOG4CXX_STR("witness/rolling/multiprocess-test.1"))));
	}

	/**
	 * Test a time based rolling policy with a sized based trigger.
	 */
	void test2()
	{
		LogString expectedPrefix = LOG4CXX_STR("multiprocess-dated-");
		// remove any previously generated files
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			LogString filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() < filename.size() &&
				filename.substr(0, expectedPrefix.size()) == expectedPrefix)
				std::filesystem::remove(dir_entry);
		}
		auto logger = getLogger(LOG4CXX_STR("Test2"));
		auto approxBytesPerLogEvent = 40 + 23;
		auto requiredLogFileCount = 3;
		size_t approxBytesPerLogFile = 1000;
		if (auto pAppender = LOG4CXX_NS::cast<rolling::RollingFileAppender>(logger->getAppender(LOG4CXX_STR("DATED"))))
		{
			if (auto pPolicy = LOG4CXX_NS::cast<rolling::SizeBasedTriggeringPolicy>(pAppender->getTriggeringPolicy()))
				approxBytesPerLogFile = pPolicy->getMaxFileSize();
		}
		auto requiredLogEventCount = (approxBytesPerLogFile * requiredLogFileCount + approxBytesPerLogEvent - 1) / approxBytesPerLogEvent;
		for ( int x = 0; x < requiredLogEventCount; x++ )
		{
			LOG4CXX_INFO( logger, "This is test message " << x );
		}

		// Count rolled files
		helpers::Pool p;
		helpers::StrftimeDateFormat("%Y-%m-%d").format(expectedPrefix, helpers::Date::currentTime(), p);
		int fileCount = 0;
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			LogString filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() < filename.size() &&
				filename.substr(0, expectedPrefix.size()) == expectedPrefix)
				++fileCount;
		}
		LOGUNIT_ASSERT(1 < fileCount);
	}

	/**
	 * Generate about 30 rollovers per process using a time based rolling policy with a sized based trigger.
	 */
	void test3()
	{
		auto logger = getLogger(LOG4CXX_STR("Test3"));
		auto approxBytesPerLogEvent = 40 + 23;
		auto requiredLogFileCount = 30;
		size_t approxBytesPerLogFile = 1000;
		if (auto pAppender = LOG4CXX_NS::cast<rolling::RollingFileAppender>(logger->getAppender(LOG4CXX_STR("DATED-UNCOMPRESSED"))))
		{
			if (auto pPolicy = LOG4CXX_NS::cast<rolling::SizeBasedTriggeringPolicy>(pAppender->getTriggeringPolicy()))
				approxBytesPerLogFile = pPolicy->getMaxFileSize();
		}
		auto requiredLogEventCount = (approxBytesPerLogFile * requiredLogFileCount + approxBytesPerLogEvent - 1) / approxBytesPerLogEvent;
		for ( int x = 0; x < requiredLogEventCount; x++ )
		{
			LOG4CXX_INFO( logger, "This is test message " << x );
		}
	}

	/**
	 * Concurrently use a time based rolling policy with a sized based trigger.
	 */
	void test4()
	{
		LogString expectedPrefix = LOG4CXX_STR("multiprocess-dated");
		// remove any previously generated files
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			LogString filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() < filename.size() &&
				filename.substr(0, expectedPrefix.size()) == expectedPrefix)
				std::filesystem::remove(dir_entry);
		}
		auto thisProgram = GetExecutableFileName();
		const char* args[] = {thisProgram.c_str(), "test3", 0};
		helpers::Pool p;
		apr_procattr_t* attr = NULL;
		setTestAttributes(&attr, p);
		apr_proc_t pid[5];
		for (auto i : {0, 1, 2, 3, 4})
			startTestInstance(&pid[i], attr, args, p);
		for (auto i : {0, 1, 2, 3, 4})
		{
			int exitCode;
			apr_exit_why_e reason;
			apr_proc_wait(&pid[i], &exitCode, &reason, APR_WAIT);
			LOGUNIT_ASSERT_EQUAL(exitCode, 0);
		}

		// Check all messages are saved to files
		LogString expectedSuffix = LOG4CXX_STR(".log");
		std::vector<int> messageCount;
		std::map<long long, int> perThreadMessageCount;
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			LogString filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() + expectedSuffix.size() <= filename.size()
				&& filename.substr(0, expectedPrefix.size()) == expectedPrefix
				&& filename.substr(filename.size() - expectedSuffix.size()) == expectedSuffix)
			{
				std::ifstream input(dir_entry.path());
				for (std::string line; std::getline(input, line);)
				{
					 auto pos = line.rfind(' ');
					 if (line.npos != pos && pos + 1 < line.size())
					 {
						try
						{
							auto msgNumber = std::stoi(line.substr(pos));
							if (messageCount.size() <= msgNumber)
								messageCount.resize(msgNumber + 1);
							++messageCount[msgNumber];
						}
						catch (std::exception const& ex)
						{
							LogString msg(ex.what());
							msg += " processing\n";
							msg += line;
							helpers::LogLog::warn(msg);
						}
					 }
					 pos = line.find(" [0x");
					 if (line.npos != pos && pos + 4 < line.size())
					 {
						try
						{
							auto threadNumber = std::stoll(line.substr(pos + 4), 0, 16);
							++perThreadMessageCount[threadNumber];
						}
						catch (std::exception const& ex)
						{
							LogString msg(ex.what());
							msg += " processing\n";
							msg += line;
							helpers::LogLog::warn(msg);
						}
					 }
				}
			}
		}
		if (helpers::LogLog::isDebugEnabled())
		{
			LogString msg(LOG4CXX_STR("messageCount "));
			for (auto item : messageCount)
			{
				msg += logchar(' ');
				helpers::StringHelper::toString(item, p, msg);
			}
			helpers::LogLog::debug(msg);
		}
		if (helpers::LogLog::isDebugEnabled())
		{
			LogString msg(LOG4CXX_STR("perThreadMessageCount "));
			for (auto item : perThreadMessageCount)
			{
				msg += logchar(' ');
				helpers::StringHelper::toString(item.second, p, msg);
			}
			helpers::LogLog::debug(msg);
		}
		for (auto& count : messageCount)
			LOGUNIT_ASSERT_EQUAL(count, messageCount.front());
	}

private:

	void setTestAttributes(apr_procattr_t** attr, helpers::Pool& p)
	{
		if (apr_procattr_create(attr, p.getAPRPool()) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_create failed");
		}
		if (apr_procattr_io_set(*attr, APR_NO_PIPE, APR_NO_PIPE, APR_NO_PIPE) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_io_set failed");
		}
		if (apr_procattr_cmdtype_set(*attr, APR_PROGRAM) != APR_SUCCESS)
		{
			LOGUNIT_FAIL("apr_procattr_cmdtype_set failed");
		}
	}

	void startTestInstance(apr_proc_t* pid, apr_procattr_t* attr, const char** argv, helpers::Pool& p)
	{
		if (apr_proc_create(pid, argv[0], argv, NULL, attr, p.getAPRPool()) == APR_SUCCESS)
		{
			apr_sleep(1000);    // 1 millisecond
		}
		else
		{
			LOGUNIT_FAIL("apr_proc_create failed");
		}
	}

	std::string GetExecutableFileName()
	{
		static const int bufSize = 4096;
		char buf[bufSize+1] = {0};
		uint32_t bufCount = 0;
#if defined(_WIN32)
		GetModuleFileName(NULL, buf, bufSize);
#elif defined(__APPLE__)
		_NSGetExecutablePath(buf, &bufCount);
#elif (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 500) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
		std::ostringstream exeLink;
		exeLink << "/proc/" << getpid() << "/exe";
		bufCount = readlink(exeLink.str().c_str(), buf, bufSize);
		if (0 < bufCount)
			buf[bufCount] = 0;
#else
		strncpy(buf, "multiprocessrollingtest", bufSize);
#endif
		return std::string(buf);
	}
#ifdef _DEBUG
	struct Fixture
	{
		Fixture() {
			helpers::LogLog::setInternalDebugging(true);
		}
	} suiteFixture;
#endif

};

LOGUNIT_TEST_SUITE_REGISTRATION(MultiprocessRollingTest);

