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
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/helpers/fileoutputstream.h>
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
		auto logger = getLogger("Test1");
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
		std::string expectedPrefix{ "multiprocess-2-" };
		// remove any previously generated files
		std::filesystem::path outputDir("output/rolling");
		if (!exists(outputDir))
			;
		else for (auto const& dir_entry : std::filesystem::directory_iterator{outputDir})
		{
			std::string filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() < filename.size() &&
				filename.substr(0, expectedPrefix.size()) == expectedPrefix)
				std::filesystem::remove(dir_entry);
		}
		auto logger = getLogger("Test2");
		auto approxBytesPerLogEvent = 40 + 23;
		auto requiredLogFileCount = 3;
		size_t approxBytesPerLogFile = 1000;
		if (auto pAppender = LOG4CXX_NS::cast<rolling::RollingFileAppender>(logger->getAppender(LOG4CXX_STR("DATED"))))
		{
			if (auto pPolicy = LOG4CXX_NS::cast<rolling::SizeBasedTriggeringPolicy>(pAppender->getTriggeringPolicy()))
				approxBytesPerLogFile = pPolicy->getMaxFileSize();
		}
		auto requiredLogEventCount = (approxBytesPerLogFile * requiredLogFileCount + approxBytesPerLogEvent - 1) / approxBytesPerLogEvent;
		for ( size_t x = 0; x < requiredLogEventCount; x++ )
		{
			LOG4CXX_INFO( logger, "This is test message " << x );
		}

		// Count rolled files
		LOG4CXX_DECODE_CHAR(expectedPrefixLS, expectedPrefix);
		helpers::Pool p;
		helpers::StrftimeDateFormat(LOG4CXX_STR("%Y-%m-%d")).format(expectedPrefixLS, helpers::Date::currentTime(), p);
		LOG4CXX_ENCODE_CHAR(rolledPrefix, expectedPrefixLS);
		int fileCount = 0;
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			std::string filename(dir_entry.path().filename().string());
			if (rolledPrefix.size() < filename.size() &&
				filename.substr(0, rolledPrefix.size()) == rolledPrefix)
				++fileCount;
		}
		LOGUNIT_ASSERT(1 < fileCount);
	}

	/**
	 * Generate about 30 rollovers per process using a time based rolling policy with a sized based trigger.
	 */
	void test3()
	{
		auto logger = getLogger("Test3");
		auto approxBytesPerLogEvent = 40 + 23;
		auto requiredLogFileCount = 30;
		size_t approxBytesPerLogFile = 1000;
		if (auto pAppender = LOG4CXX_NS::cast<rolling::RollingFileAppender>(logger->getAppender(LOG4CXX_STR("DATED-UNCOMPRESSED"))))
		{
			if (auto pPolicy = LOG4CXX_NS::cast<rolling::SizeBasedTriggeringPolicy>(pAppender->getTriggeringPolicy()))
				approxBytesPerLogFile = pPolicy->getMaxFileSize();
		}
		auto requiredLogEventCount = (approxBytesPerLogFile * requiredLogFileCount + approxBytesPerLogEvent - 1) / approxBytesPerLogEvent;
		for ( size_t x = 0; x < requiredLogEventCount; x++ )
		{
			LOG4CXX_INFO( logger, "This is test message " << x );
		}
	}

	/**
	 * Concurrently use a time based rolling policy with a sized based trigger.
	 */
	void test4()
	{
		std::string expectedPrefix("multiprocess-3");
		// remove any previously generated files
		std::filesystem::path outputDir("output/rolling");
		if (!exists(outputDir))
			;
		else for (auto const& dir_entry : std::filesystem::directory_iterator{outputDir})
		{
			std::string filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() < filename.size() &&
				filename.substr(0, expectedPrefix.size()) == expectedPrefix)
				std::filesystem::remove(dir_entry);
		}
		helpers::FileOutputStream output(LOG4CXX_STR("output/rolling/multiprocess-test4-child.log"), false);
		auto thisProgram = GetExecutableFileName();
		bool thisProgramExists = std::filesystem::exists(thisProgram);
		if (!thisProgramExists && helpers::LogLog::isDebugEnabled())
			helpers::LogLog::debug(LOG4CXX_STR("thisProgram: ") + thisProgram);
		LOGUNIT_ASSERT(thisProgramExists);
		const char* args[] = {thisProgram.c_str(), "test3", 0};
		helpers::Pool p;
		apr_procattr_t* attr = NULL;
		setTestAttributes(&attr, output.getFilePtr(), p);
		apr_proc_t pid[5];
		auto startTime = helpers::Date::currentTime();
		for (auto i : {0, 1, 2, 3, 4})
			startTestInstance(&pid[i], attr, args, p);
		for (auto i : {0, 1, 2, 3, 4})
		{
			int exitCode;
			apr_exit_why_e reason;
			apr_proc_wait(&pid[i], &exitCode, &reason, APR_WAIT);
			if (exitCode != 0 && helpers::LogLog::isDebugEnabled())
			{
				LogString msg = LOG4CXX_STR("child: ");
				helpers::StringHelper::toString(i, p, msg);
				msg += LOG4CXX_STR("; exit code: ");
				helpers::StringHelper::toString(exitCode, p, msg);
				msg += LOG4CXX_STR("; reason: ");
				helpers::StringHelper::toString(reason, p, msg);
				helpers::LogLog::debug(msg);
			}
			LOGUNIT_ASSERT_EQUAL(exitCode, 0);
		}
		if (helpers::LogLog::isDebugEnabled())
		{
			LogString msg;
			auto currentTime = helpers::Date::currentTime();
			msg += LOG4CXX_STR("elapsed ");
			helpers::StringHelper::toString(currentTime - startTime, p, msg);
			helpers::LogLog::debug(msg);
		}

		// Check all messages are saved to files
		std::string expectedSuffix(".log");
		std::vector<int> messageCount;
		std::map<long long, int> perThreadMessageCount;
		for (auto const& dir_entry : std::filesystem::directory_iterator{"output/rolling"})
		{
			std::string filename(dir_entry.path().filename().string());
			if (expectedPrefix.size() + expectedSuffix.size() <= filename.size()
				&& filename.substr(0, expectedPrefix.size()) == expectedPrefix
				&& filename.substr(filename.size() - expectedSuffix.size()) == expectedSuffix)
			{
				auto initialPerThreadMessageCount = perThreadMessageCount;
				std::ifstream input(dir_entry.path());
				for (std::string line; std::getline(input, line);)
				{
					 auto pos = line.rfind(' ');
					 if (line.npos != pos && pos + 1 < line.size())
					 {
						try
						{
							auto msgNumber = std::stoull(line.substr(pos));
							if (messageCount.size() <= msgNumber)
								messageCount.resize(msgNumber + 1);
							++messageCount[msgNumber];
						}
						catch (std::exception const& ex)
						{
							LogString msg;
							helpers::Transcoder::decode(ex.what(), msg);
							msg += LOG4CXX_STR(" processing\n");
							helpers::Transcoder::decode(line, msg);
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
							LogString msg;
							helpers::Transcoder::decode(ex.what(), msg);
							msg += LOG4CXX_STR(" processing\n");
							helpers::Transcoder::decode(line, msg);
							helpers::LogLog::warn(msg);
						}
					 }
				}
				if (helpers::LogLog::isDebugEnabled())
				{
					LogString msg;
					helpers::Transcoder::decode(dir_entry.path().filename().string(), msg);
					msg += LOG4CXX_STR(": perThreadMessageCount ");
					for (auto item : perThreadMessageCount)
					{
						msg += logchar(' ');
						helpers::StringHelper::toString(item.second - initialPerThreadMessageCount[item.first], p, msg);
					}
					helpers::LogLog::debug(msg);
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
		if (apr_proc_create(pid, argv[0], argv, NULL, attr, p.getAPRPool()) == APR_SUCCESS)
		{
			apr_sleep(1000);    // 1 millisecond
		}
		else
		{
			LOGUNIT_FAIL("apr_proc_create");
		}
	}

	std::string GetExecutableFileName()
	{
		auto lsProgramFilePath = Configurator::configurationProperties().getProperty(LOG4CXX_STR("PROGRAM_FILE_PATH"));
		LOG4CXX_ENCODE_CHAR(programFilePath, lsProgramFilePath);
		return programFilePath;
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
