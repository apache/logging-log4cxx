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
#include <log4cxx/fileappender.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include "logunit.h"
#include <apr_time.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

auto getLogger(const std::string& name = std::string()) -> LoggerPtr {
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
	LOGUNIT_TEST(testBufferedOutput);
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

	void testBufferedOutput()
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
};

LOGUNIT_TEST_SUITE_REGISTRATION(FileAppenderTest);

