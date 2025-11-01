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
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#include "logunit.h"
#include <apr_time.h>
#include <apr_thread_proc.h>
#include <fstream>

using namespace log4cxx;
using namespace log4cxx::helpers;

auto getLogger(const LogString& name = {}) -> LoggerPtr {
	static struct log4cxx_initializer {
		log4cxx_initializer() {
			auto layout = std::make_shared<PatternLayout>(LOG4CXX_STR("%d %m%n"));
			auto writer = std::make_shared<FileAppender>(layout, LOG4CXX_STR("output/newdir/temp.log"), false);
			writer->setName(LOG4CXX_STR("FileAppender"));
			writer->setBufferedIO(true);
			writer->setBufferedSeconds(1);
			helpers::Pool p;
			writer->activateOptions(p);
			BasicConfigurator::configure(writer);
		}
		~log4cxx_initializer() {
			LogManager::shutdown();
		}
	} initAndShutdown;
	return name.empty()
		? LogManager::getRootLogger()
		: LogManager::getLogger(name);
}


/**
 *
 * FileAppender tests.
 */
LOGUNIT_CLASS(FileAppenderTest)
{
	LOGUNIT_TEST_SUITE(FileAppenderTest);
	LOGUNIT_TEST(testDirectoryCreation);
	LOGUNIT_TEST(testgetSetThreshold);
	LOGUNIT_TEST(testIsAsSevereAsThreshold);
	LOGUNIT_TEST(testPeriodicFlush);
	LOGUNIT_TEST(writeFinalBufferOutput);
	LOGUNIT_TEST(checkFinalBufferOutput);
	LOGUNIT_TEST_SUITE_END();

#ifdef _DEBUG
	struct Fixture
	{
		Fixture() {
			helpers::LogLog::setInternalDebugging(true);
		}
	} suiteFixture;
#endif

public:
	/**
	 * Tests that any necessary directories are attempted to
	 * be created if they don't exist.  See bug 9150.
	 *
	 */
	void testDirectoryCreation()
	{
		File newFile(LOG4CXX_STR("output/newdir/temp.log"));
		Pool p;
		newFile.deleteFile(p);

		File newDir(LOG4CXX_STR("output/newdir"));
		newDir.deleteFile(p);

		FileAppenderPtr wa(new FileAppender());
		wa->setFile(LOG4CXX_STR("output/newdir/temp.log"));
		wa->setLayout(PatternLayoutPtr(new PatternLayout(LOG4CXX_STR("%m%n"))));
		wa->activateOptions(p);

		LOGUNIT_ASSERT(File(LOG4CXX_STR("output/newdir/temp.log")).exists(p));
	}

	/**
	 * Tests getThreshold and setThreshold.
	 */
	void testgetSetThreshold()
	{
		FileAppenderPtr appender = FileAppenderPtr(new FileAppender());
		LevelPtr debug = Level::getDebug();
		//
		//  different from log4j where threshold is null.
		//
		LOGUNIT_ASSERT_EQUAL(Level::getAll(), appender->getThreshold());
		appender->setThreshold(debug);
		LOGUNIT_ASSERT_EQUAL(debug, appender->getThreshold());
	}

	/**
	 * Tests isAsSevereAsThreshold.
	 */
	void testIsAsSevereAsThreshold()
	{
		FileAppenderPtr appender = FileAppenderPtr(new FileAppender());
		LevelPtr debug = Level::getDebug();
		LOGUNIT_ASSERT(appender->isAsSevereAsThreshold(debug));
	}

	// Check a file is periodically flushed
	void testPeriodicFlush()
	{
		auto logger = getLogger();
		int requiredMsgCount = 10000;
		for ( int x = 0; x < requiredMsgCount; x++ )
		{
			LOG4CXX_INFO( logger, "This is test message " << x );
		}
		auto appender = log4cxx::cast<FileAppender>(logger->getAppender(LOG4CXX_STR("FileAppender")));
		LOGUNIT_ASSERT(appender);
		File file(appender->getFile());
		Pool p;
		size_t initialLength = file.length(p);

		// wait 1.2 sec and check the buffer is flushed
		apr_sleep(1200000);
		size_t flushedLength = file.length(p);

		// Check the file extended
		if (helpers::LogLog::isDebugEnabled())
		{
			LogString msg(LOG4CXX_STR("initialLength "));
			helpers::StringHelper::toString(initialLength, p, msg);
			msg += LOG4CXX_STR(" flushedLength ");
			helpers::StringHelper::toString(flushedLength, p, msg);
			helpers::LogLog::debug(msg);
		}
		LOGUNIT_ASSERT(initialLength < flushedLength);
	}

	// Used to check the buffer is flushed at exit
	void writeFinalBufferOutput()
	{
		int requiredMsgCount = 100;
		auto logger = getLogger(LOG4CXX_STR("100message"));

		// Set up a new file
		LogString dir{ LOG4CXX_STR("output/newdir") };
		auto writer = std::make_shared<rolling::RollingFileAppender>();
		writer->setLayout(std::make_shared<PatternLayout>(LOG4CXX_STR("%d %m%n")));
		writer->setFile(dir + LOG4CXX_STR("/100message.log"));
		writer->setBufferedIO(true);
		writer->setBufferedSeconds(1);
		auto policy = std::make_shared<rolling::TimeBasedRollingPolicy>();
		policy->setFileNamePattern(dir + LOG4CXX_STR("/100message-%d{yyyy}.log"));
		writer->setRollingPolicy(policy);
		helpers::Pool p;
		writer->activateOptions(p);
		logger->setAdditivity(false);
		logger->addAppender(writer);

		for ( int x = 0; x < requiredMsgCount; x++ )
		{
			LOG4CXX_INFO( logger, "This is test message " << x );
		}
	}

	void checkFinalBufferOutput()
	{
		helpers::Pool p;
		// start a separate instance of this to write messages to the file
		helpers::FileOutputStream output(LOG4CXX_STR("output/newdir/100message-writer.out"), false);
		auto thisProgram = GetExecutableFileName();
		const char* args[] = {thisProgram.c_str(), "writeFinalBufferOutput", 0};
		apr_procattr_t* attr = NULL;
		setTestAttributes(&attr, output.getFilePtr(), p);
		apr_proc_t pid;
		startTestInstance(&pid, attr, args, p);

		int exitCode;
		apr_exit_why_e reason;
		apr_proc_wait(&pid, &exitCode, &reason, APR_WAIT);
		if (exitCode != 0)
		{
			LogString msg = LOG4CXX_STR("child exit code: ");
			helpers::StringHelper::toString(exitCode, p, msg);
			msg += LOG4CXX_STR("; reason: ");
			helpers::StringHelper::toString(reason, p, msg);
			helpers::LogLog::warn(msg);
		}
		LOGUNIT_ASSERT_EQUAL(exitCode, 0);

		// Check all required messages are in the file
		std::ifstream input("output/newdir/100message.log");
		std::vector<int> messageCount;
		int lineCount{ 0 };
		for (std::string line; std::getline(input, line);)
		{
			++lineCount;
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
		}
		LogString msg = LOG4CXX_STR("lineCount: ");
		helpers::StringHelper::toString(lineCount, p, msg);
		helpers::LogLog::debug(msg);
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

LOGUNIT_TEST_SUITE_REGISTRATION(FileAppenderTest);

