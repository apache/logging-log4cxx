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

#define NOMINMAX
#include "logunit.h"

#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/simplelayout.h>
#include "vectorappender.h"
#include <log4cxx/asyncappender.h>
#include "appenderskeletontestcase.h"
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/varia/fallbackerrorhandler.h>
#include <apr_strings.h>
#include "testchar.h"
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/file.h>
#include <thread>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

class NullPointerAppender : public AppenderSkeleton
{
	public:
		NullPointerAppender()
		{
		}


		/**
		 * @{inheritDoc}
		 */
		void append(const spi::LoggingEventPtr&, log4cxx::helpers::Pool&) override
		{
			throw NullPointerException(LOG4CXX_STR("Intentional NullPointerException"));
		}

		void close() override
		{
		}

		bool requiresLayout() const override
		{
			return false;
		}
};

/**
 * Vector appender that can be explicitly blocked.
 */
class BlockableVectorAppender : public VectorAppender
{
	private:
		std::mutex blocker;
	public:
		/**
		 * Create new instance.
		 */
		BlockableVectorAppender()
		{
		}

		/**
		 * {@inheritDoc}
		 */
		void append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p) override
		{
			std::lock_guard<std::mutex> lock( blocker );
			VectorAppender::append(event, p);

			//
			//   if fatal, echo messages for testLoggingInDispatcher
			//
			if (event->getLevel() == Level::getInfo())
			{
				LoggerPtr logger = Logger::getLoggerLS(event->getLoggerName());
				LOG4CXX_LOGLS(logger, Level::getError(), event->getMessage());
				LOG4CXX_LOGLS(logger, Level::getWarn(), event->getMessage());
				LOG4CXX_LOGLS(logger, Level::getInfo(), event->getMessage());
				LOG4CXX_LOGLS(logger, Level::getDebug(), event->getMessage());
			}
		}

		std::mutex& getBlocker()
		{
			return blocker;
		}

};

LOG4CXX_PTR_DEF(BlockableVectorAppender);

/**
 * Tests of AsyncAppender.
 */
class AsyncAppenderTestCase : public AppenderSkeletonTestCase
{
		LOGUNIT_TEST_SUITE(AsyncAppenderTestCase);
		//
		// tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);

		LOGUNIT_TEST(closeTest);
		LOGUNIT_TEST(test2);
		LOGUNIT_TEST(testEventFlush);
		LOGUNIT_TEST(testMultiThread);
		LOGUNIT_TEST(testBadAppender);
		LOGUNIT_TEST(testBufferOverflowBehavior);
#if LOG4CXX_HAS_DOMCONFIGURATOR
		LOGUNIT_TEST(testConfiguration);
#endif
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
		void setUp()
		{
			AppenderSkeletonTestCase::setUp();
		}

		void tearDown()
		{
			LogManager::shutdown();
			AppenderSkeletonTestCase::tearDown();
		}

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new AsyncAppender();
		}

		// this test checks whether it is possible to write to a closed AsyncAppender
		void closeTest()
		{
			LoggerPtr root = Logger::getRootLogger();
			LayoutPtr layout = LayoutPtr(new SimpleLayout());
			VectorAppenderPtr vectorAppender = VectorAppenderPtr(new VectorAppender());
			AsyncAppenderPtr asyncAppender = AsyncAppenderPtr(new AsyncAppender());
			asyncAppender->setName(LOG4CXX_STR("async-CloseTest"));
			asyncAppender->addAppender(vectorAppender);
			root->addAppender(asyncAppender);

			root->debug(LOG4CXX_TEST_STR("m1"));
			asyncAppender->close();
			root->debug(LOG4CXX_TEST_STR("m2"));

			const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL((size_t) 1, v.size());
		}

		// this test checks whether appenders embedded within an AsyncAppender are also
		// closed
		void test2()
		{
			LoggerPtr root = Logger::getRootLogger();
			LayoutPtr layout = SimpleLayoutPtr(new SimpleLayout());
			VectorAppenderPtr vectorAppender = VectorAppenderPtr(new VectorAppender());
			AsyncAppenderPtr asyncAppender = AsyncAppenderPtr(new AsyncAppender());
			asyncAppender->setName(LOG4CXX_STR("async-test2"));
			asyncAppender->addAppender(vectorAppender);
			root->addAppender(asyncAppender);

			root->debug(LOG4CXX_TEST_STR("m1"));
			asyncAppender->close();
			root->debug(LOG4CXX_TEST_STR("m2"));

			const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL((size_t) 1, v.size());
			LOGUNIT_ASSERT(vectorAppender->isClosed());
		}

		// this test checks all messages are delivered when an AsyncAppender is closed
		void testEventFlush()
		{
			size_t LEN = 200; // Larger than default buffer size (128)
			LoggerPtr root = Logger::getRootLogger();
			VectorAppenderPtr vectorAppender = VectorAppenderPtr(new VectorAppender());
			vectorAppender->setMillisecondDelay(1);
			AsyncAppenderPtr asyncAppender = AsyncAppenderPtr(new AsyncAppender());
			asyncAppender->setName(LOG4CXX_STR("async-testEventFlush"));
			asyncAppender->addAppender(vectorAppender);
			root->addAppender(asyncAppender);

			for (size_t i = 0; i < LEN; i++)
			{
				LOG4CXX_DEBUG(root, "message" << i);
			}

			asyncAppender->close();
			root->debug(LOG4CXX_STR("m2"));

			const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(LEN, v.size());
			Pool p;
			for (size_t i = 0; i < LEN; i++)
			{
				LogString m(LOG4CXX_STR("message"));
				StringHelper::toString(i, p, m);
				LOGUNIT_ASSERT(v[i]->getMessage() == m);
			}
			LOGUNIT_ASSERT_EQUAL(true, vectorAppender->isClosed());
		}


		// this test checks all messages are delivered from multiple threads
		void testMultiThread()
		{
			int LEN = 2000; // Larger than default buffer size (128)
			auto threadCount = std::max(static_cast<int>(std::thread::hardware_concurrency() - 1), 2);
			auto root = Logger::getRootLogger();
			auto vectorAppender = std::make_shared<VectorAppender>();
			auto asyncAppender = std::make_shared<AsyncAppender>();
			asyncAppender->setName(LOG4CXX_STR("async-testMultiThread"));
			asyncAppender->addAppender(vectorAppender);
			root->addAppender(asyncAppender);

			std::vector<std::thread> threads;
			for ( int x = 0; x < threadCount; x++ )
			{
				threads.emplace_back([root, LEN]()
				{
					for (int i = 0; i < LEN; i++)
					{
						LOG4CXX_DEBUG(root, "message" << i);
					}
				});
			}

			for ( auto& thr : threads )
			{
				if ( thr.joinable() )
				{
					thr.join();
				}
			}
			asyncAppender->close();

			const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(LEN*threadCount, (int)v.size());
			std::map<LogString, int> perThreadCount;
			std::vector<int> msgCount(LEN, 0);
			for (auto m : v)
			{
				auto i = StringHelper::toInt(m->getMessage().substr(7));
				LOGUNIT_ASSERT(0 <= i);
				LOGUNIT_ASSERT(i < LEN);
				++msgCount[i];
				++perThreadCount[m->getThreadName()];
			}
			LOGUNIT_ASSERT_EQUAL(threadCount, (int)perThreadCount.size());
			for (auto& item : perThreadCount)
			{
				LOGUNIT_ASSERT_EQUAL(item.second, LEN);
			}
			for (size_t i = 0; i < LEN; i++)
				LOGUNIT_ASSERT_EQUAL(msgCount[i], threadCount);
		}

		/**
		 * Checks that async will switch a bad appender to another appender.
		 */
		void testBadAppender()
		{
			AppenderPtr nullPointerAppender(new NullPointerAppender());
			AsyncAppenderPtr asyncAppender(new AsyncAppender());
			asyncAppender->setName(LOG4CXX_STR("async-testBadAppender"));
			asyncAppender->addAppender(nullPointerAppender);
			asyncAppender->setBufferSize(5);
			Pool p;
			asyncAppender->activateOptions(p);
			LoggerPtr root = Logger::getRootLogger();
			root->addAppender(asyncAppender);

			varia::FallbackErrorHandlerPtr errorHandler(new varia::FallbackErrorHandler());
			errorHandler->setAppender(asyncAppender);
			VectorAppenderPtr vectorAppender(new VectorAppender());
			vectorAppender->setName(LOG4CXX_STR("async-memoryAppender"));
			errorHandler->setBackupAppender(vectorAppender);
			errorHandler->setLogger(root);
			asyncAppender->setErrorHandler(errorHandler);

			LOG4CXX_INFO(root, "Message");
			std::this_thread::sleep_for( std::chrono::milliseconds( 30 ) );
			LOGUNIT_ASSERT(errorHandler->errorReported());
			LOG4CXX_INFO(root, "Message");
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT(0 < v.size());
		}

		/**
		 * Tests behavior when the the async buffer overflows.
		 */
		void testBufferOverflowBehavior()
		{
			BlockableVectorAppenderPtr blockableAppender = BlockableVectorAppenderPtr(new BlockableVectorAppender());
			blockableAppender->setName(LOG4CXX_STR("async-blockableVector"));
			AsyncAppenderPtr async = AsyncAppenderPtr(new AsyncAppender());
			async->setName(LOG4CXX_STR("async-testBufferOverflowBehavior"));
			async->addAppender(blockableAppender);
			async->setBufferSize(5);
			async->setLocationInfo(true);
			async->setBlocking(false);
			Pool p;
			async->activateOptions(p);
			LoggerPtr rootLogger = Logger::getRootLogger();
			rootLogger->addAppender(async);
			LOG4CXX_INFO(rootLogger, "Hello, World"); // This causes the dispatch thread creation
			std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) ); // Wait for the dispatch thread  to be ready
			{
				std::lock_guard<std::mutex> sync(blockableAppender->getBlocker());

				for (int i = 0; i < 140; i++)
				{
					LOG4CXX_INFO(rootLogger, "Hello, World");
				}

				LOG4CXX_ERROR(rootLogger, "That's all folks.");
			}
			async->close();
			const std::vector<spi::LoggingEventPtr>& events = blockableAppender->getVector();
			LOGUNIT_ASSERT(!events.empty());
			LoggingEventPtr initialEvent = events.front();
			LoggingEventPtr discardEvent = events.back();
			LOGUNIT_ASSERT(initialEvent->getMessage() == LOG4CXX_STR("Hello, World"));
			LOGUNIT_ASSERT(discardEvent->getMessage().substr(0, 10) == LOG4CXX_STR("Discarded "));
			LOGUNIT_ASSERT_EQUAL(log4cxx::spi::LocationInfo::getLocationUnavailable().getClassName(),
				discardEvent->getLocationInformation().getClassName());
		}

#if LOG4CXX_HAS_DOMCONFIGURATOR
		void testConfiguration()
		{
			log4cxx::xml::DOMConfigurator::configure("input/xml/asyncAppender1.xml");
			AsyncAppenderPtr asyncAppender = log4cxx::cast<AsyncAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("ASYNC")));
			LOGUNIT_ASSERT(!(asyncAppender == 0));
			LOGUNIT_ASSERT_EQUAL(100, asyncAppender->getBufferSize());
			LOGUNIT_ASSERT_EQUAL(false, asyncAppender->getBlocking());
			LOGUNIT_ASSERT_EQUAL(true, asyncAppender->getLocationInfo());
			AppenderList nestedAppenders(asyncAppender->getAllAppenders());
			// TODO:
			// test seems to work okay, but have not found a working way to
			// get a reference to the nested vector appender
			//
			// LOGUNIT_ASSERT_EQUAL((size_t) 1, nestedAppenders.size());
			// VectorAppenderPtr vectorAppender(nestedAppenders[0]);
			// LOGUNIT_ASSERT(0 != vectorAppender);
			LoggerPtr root(Logger::getRootLogger());

			size_t LEN = 20;

			for (size_t i = 0; i < LEN; i++)
			{
				LOG4CXX_DEBUG(root, "message" << i);
			}

			asyncAppender->close();
			// const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
			// LOGUNIT_ASSERT_EQUAL(LEN, v.size());
			// LOGUNIT_ASSERT_EQUAL(true, vectorAppender->isClosed());
		}
#endif


};

LOGUNIT_TEST_SUITE_REGISTRATION(AsyncAppenderTestCase);
