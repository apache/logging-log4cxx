/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "logunit.h"

#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/pool.h>
#include <thread>
#include <vector>

using log4cxx::Logger;
using log4cxx::LoggerPtr;
using log4cxx::LogManager;
using log4cxx::LogString;
using log4cxx::helpers::LogLog;
using log4cxx::helpers::StringHelper;
using log4cxx::helpers::Pool;

struct MockAppender : public log4cxx::AppenderSkeleton{
	log4cxx_int64_t messageCount = 0;
	MockAppender(){
		setName(LOG4CXX_STR("mock_appender"));
	}

	void close() override {}

	bool requiresLayout() const override {
		return false;
	}

	void append(const log4cxx::spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p) override {
		++messageCount;
	}
};

LOGUNIT_CLASS(ThroughputTests){
	LOGUNIT_TEST_SUITE(ThroughputTests);
	LOGUNIT_TEST(enabledSingleThreadMessageBenchmark);
	LOGUNIT_TEST(disabledSingleThreadMessageBenchmark);
	LOGUNIT_TEST(enabledMultiThreadMessageBenchmark);
	LOGUNIT_TEST(disabledMultiThreadMessageBenchmark);
	LOGUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
		Logger::getRootLogger()->removeAllAppenders();
		std::shared_ptr<MockAppender> nullWriter( new MockAppender() );
		Logger::getRootLogger()->addAppender( nullWriter );
	}

	void tearDown()
	{
//		root->getLoggerRepository()->resetConfiguration();
	}

	static void info_logger( int times ){
		LoggerPtr logger = LogManager::getLogger( "test.multithreaded" );
		for( int x = 0; x < times; ++x ){
			LOG4CXX_INFO( logger, "This is a test message that has some data" );
		}
	}

	static void trace_logger( int times ){
		LoggerPtr logger = LogManager::getLogger( "test.multithreaded" );
		for( int x = 0; x < times; ++x ){
			LOG4CXX_TRACE( logger, "This is a test message that has some data" );
		}
	}
	using level_logger = void (*)(int times);

	void singleThreadBenchmark(const LogString& name, level_logger logging_func, int msgCount){
		std::vector<std::thread> threads;
		auto startTick = clock();
		logging_func(msgCount);
		auto stopTick = clock();
		auto elapsed = stopTick - startTick;
		auto milliseconds = log4cxx_int64_t(float(elapsed) / CLOCKS_PER_SEC * 1000);
		auto nanosecondsPerLog = milliseconds * 1000000 / msgCount;
		Pool pool;
		LogString msg;
		msg += name;
		msg += LOG4CXX_STR(": ");
		StringHelper::toString(nanosecondsPerLog, pool, msg);
		msg += LOG4CXX_STR(" ns/log ");
		StringHelper::toString(msgCount, pool, msg);
		msg += LOG4CXX_STR(" messages ");
		StringHelper::toString(milliseconds, pool, msg);
		msg += LOG4CXX_STR(" ms elapsed ");
		LogLog::setInternalDebugging(true);
		LogLog::debug(msg);
	}

	void enabledSingleThreadMessageBenchmark(){
#ifdef _DEBUG
		auto msgCount = 2000;
#else
		auto msgCount = 200000;
#endif
		log4cxx_int64_t startMessageCount = 0;
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			startMessageCount = mockAppender->messageCount;
		singleThreadBenchmark(LOG4CXX_STR("Enabled"), info_logger, msgCount);
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			LOGUNIT_ASSERT(startMessageCount + msgCount == mockAppender->messageCount);
	}

	void disabledSingleThreadMessageBenchmark(){
#ifdef _DEBUG
		auto msgCount = 20000;
#else
		auto msgCount = 2000000;
#endif
		log4cxx_int64_t startMessageCount = 0;
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			startMessageCount = mockAppender->messageCount;
		singleThreadBenchmark(LOG4CXX_STR("Disabled"), trace_logger, msgCount);
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			LOGUNIT_ASSERT(startMessageCount == mockAppender->messageCount);
	}

	void multithreadBenchmark(const LogString& name, level_logger logging_func, int threadCount, int msgCount){
		auto startTick = clock();
		std::vector<std::thread> threads;
		for( auto threadNumber = threadCount; 0 < threadNumber; --threadNumber ){
			std::thread thr( logging_func, msgCount );
			threads.push_back( std::move(thr) );
		}

		for( std::thread& thr : threads ){
			if( thr.joinable() ){
				thr.join();
			}
		}
		auto stopTick = clock();
		auto elapsed = stopTick - startTick;
		auto milliseconds = log4cxx_int64_t(float(elapsed) / CLOCKS_PER_SEC * 1000);
		auto nanosecondsPerLog = milliseconds * 1000000 / msgCount;
		Pool pool;
		LogString msg;
		msg += name;
		msg += LOG4CXX_STR(": ");
		StringHelper::toString(nanosecondsPerLog, pool, msg);
		msg += LOG4CXX_STR(" ns/log ");
		StringHelper::toString(msgCount, pool, msg);
		msg += LOG4CXX_STR(" messages/thread ");
		StringHelper::toString(log4cxx_int64_t(threadCount), pool, msg);
		msg += LOG4CXX_STR(" threads ");
		StringHelper::toString(milliseconds, pool, msg);
		msg += LOG4CXX_STR(" ms elapsed ");
		LogLog::setInternalDebugging(true);
		LogLog::debug(msg);
	}

	void enabledMultiThreadMessageBenchmark(){
#ifdef _DEBUG
		auto msgCount = 2000;
#else
		auto msgCount = 200000;
#endif
		auto threadCount = std::max(1, int(std::thread::hardware_concurrency() / 2));
		log4cxx_int64_t startMessageCount = 0;
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			startMessageCount = mockAppender->messageCount;
		multithreadBenchmark(LOG4CXX_STR("Enabled"), info_logger, threadCount, msgCount);
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			LOGUNIT_ASSERT(startMessageCount + msgCount * threadCount == mockAppender->messageCount);
	}

	void disabledMultiThreadMessageBenchmark(){
#ifdef _DEBUG
		auto msgCount = 20000;
#else
		auto msgCount = 2000000;
#endif
		auto threadCount = std::max(1, int(std::thread::hardware_concurrency() / 2));
		log4cxx_int64_t startMessageCount = 0;
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			startMessageCount = mockAppender->messageCount;
		multithreadBenchmark(LOG4CXX_STR("Disabled"), trace_logger, threadCount, msgCount);
		if (auto mockAppender = log4cxx::cast<MockAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("mock_appender"))))
			LOGUNIT_ASSERT(startMessageCount == mockAppender->messageCount);
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(ThroughputTests);

