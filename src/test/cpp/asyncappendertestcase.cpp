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
			std::unique_lock<std::mutex> lock( blocker );
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
		LOGUNIT_TEST(test3);
		LOGUNIT_TEST(testBadAppender);
		LOGUNIT_TEST(testLocationInfoTrue);
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

		// this test checks whether appenders embedded within an AsyncAppender are also
		// closed
		void test3()
		{
			size_t LEN = 200;
			LoggerPtr root = Logger::getRootLogger();
			VectorAppenderPtr vectorAppender = VectorAppenderPtr(new VectorAppender());
			AsyncAppenderPtr asyncAppender = AsyncAppenderPtr(new AsyncAppender());
			asyncAppender->setName(LOG4CXX_STR("async-test3"));
			asyncAppender->addAppender(vectorAppender);
			root->addAppender(asyncAppender);

			for (size_t i = 0; i < LEN; i++)
			{
				LOG4CXX_DEBUG(root, "message" << i);
			}

			asyncAppender->close();
			root->debug(LOG4CXX_TEST_STR("m2"));

			const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(LEN, v.size());
			LOGUNIT_ASSERT_EQUAL(true, vectorAppender->isClosed());
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
			std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            LOG4CXX_INFO(root, "Message");
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT(0 < v.size());
		}

		/**
		 * Tests non-blocking behavior.
		 */
		void testLocationInfoTrue()
		{
			BlockableVectorAppenderPtr blockableAppender = BlockableVectorAppenderPtr(new BlockableVectorAppender());
			blockableAppender->setName(LOG4CXX_STR("async-blockableVector"));
			AsyncAppenderPtr async = AsyncAppenderPtr(new AsyncAppender());
			async->setName(LOG4CXX_STR("async-testLocationInfoTrue"));
			async->addAppender(blockableAppender);
			async->setBufferSize(5);
			async->setLocationInfo(true);
			async->setBlocking(false);
			Pool p;
			async->activateOptions(p);
			LoggerPtr rootLogger = Logger::getRootLogger();
			rootLogger->addAppender(async);
			{
				std::unique_lock<std::mutex> sync(blockableAppender->getBlocker());

				for (int i = 0; i < 140; i++)
				{
					LOG4CXX_INFO(rootLogger, "Hello, World");
					std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
				}

				LOG4CXX_ERROR(rootLogger, "That's all folks.");
			}
			async->close();
			const std::vector<spi::LoggingEventPtr>& events = blockableAppender->getVector();
			LOGUNIT_ASSERT(events.size() > 0);
			LoggingEventPtr initialEvent = events[0];
			LoggingEventPtr discardEvent = events[events.size() - 1];
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
