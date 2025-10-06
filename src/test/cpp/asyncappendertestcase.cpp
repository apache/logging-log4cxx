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

#include <log4cxx/loggerinstance.h>
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
#include <log4cxx/propertyconfigurator.h>
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
		}

		std::mutex& getBlocker()
		{
			return blocker;
		}

};
LOG4CXX_PTR_DEF(BlockableVectorAppender);

/**
 * An appender that adds logging events
 */
class LoggingVectorAppender : public VectorAppender
{
	LoggerInstancePtr logger{ "LoggingVectorAppender" };
	void append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p) override
	{
		auto& lsMsg = event->getRenderedMessage();
		VectorAppender::append(event, p);
		if (LogString::npos != lsMsg.find(LOG4CXX_STR("World")))
		{
			LOG4CXX_LOGLS(logger, Level::getError(), LOG4CXX_STR("Some appender error"));
			LOG4CXX_LOGLS(logger, Level::getWarn(), LOG4CXX_STR("Some appender warning"));
			LOG4CXX_LOGLS(logger, Level::getInfo(), LOG4CXX_STR("Some appender information"));
			LOG4CXX_LOGLS(logger, Level::getDebug(), LOG4CXX_STR("Some appender detailed data"));
		}
	}
};
LOG4CXX_PTR_DEF(LoggingVectorAppender);

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
		LOGUNIT_TEST(testAutoMessageBufferSelection);
		LOGUNIT_TEST(testEventFlush);
		LOGUNIT_TEST(testMultiThread);
		LOGUNIT_TEST(testBadAppender);
		LOGUNIT_TEST(testBufferOverflowBehavior);
		LOGUNIT_TEST(testLoggingAppender);
#if LOG4CXX_HAS_DOMCONFIGURATOR
		LOGUNIT_TEST(testXMLConfiguration);
		LOGUNIT_TEST(testAsyncLoggerXML);
#endif
		LOGUNIT_TEST(testAsyncLoggerProperties);
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

		AppenderSkeleton* createAppenderSkeleton() const override
		{
			return new AsyncAppender();
		}

		// Check it is not possible to write to a closed AsyncAppender
		void closeTest()
		{
			AsyncAppenderPtr asyncAppender;
			auto r = LogManager::getLoggerRepository();
			r->ensureIsConfigured([r, &asyncAppender]()
			{
				asyncAppender = std::make_shared<AsyncAppender>();
				asyncAppender->setName(LOG4CXX_STR("async-CloseTest"));
				r->getRootLogger()->addAppender(asyncAppender);
				r->setConfigured(true);
			});
			LOGUNIT_ASSERT(asyncAppender);
			auto vectorAppender = std::make_shared<VectorAppender>();
			asyncAppender->addAppender(vectorAppender);

			auto root = r->getRootLogger();
			root->debug(LOG4CXX_TEST_STR("m1"));
			asyncAppender->close();
			root->debug(LOG4CXX_TEST_STR("m2"));

			// Check one message was received
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(1, int(v.size()));
			// Check appender embedded within an AsyncAppender is also closed
			LOGUNIT_ASSERT(vectorAppender->isClosed());
		}

		// Test behaviour when logging with a char type that is not logchar
		void testAutoMessageBufferSelection()
		{
			// Configure Log4cxx
			VectorAppenderPtr vectorAppender;
			auto r = LogManager::getLoggerRepository();
			r->ensureIsConfigured([r, &vectorAppender]()
			{
				vectorAppender = std::make_shared<VectorAppender>();
				r->getRootLogger()->addAppender(vectorAppender);
				r->setConfigured(true);
			});

			// Log some messages
			auto root = r->getRootLogger();
#if LOG4CXX_LOGCHAR_IS_UTF8
			LOG4CXX_INFO(root, L"Some wide string " << 42);
#else
			LOG4CXX_INFO(root, "Some narrow string " << 42);
#endif
			int expectedMessageCount = 1;
#ifdef LOG4CXX_XXXX_ASYNC_MACROS_WORK_WITH_ANY_CHAR_TYPE
			++expectedMessageCount
#if LOG4CXX_LOGCHAR_IS_UTF8
			LOG4CXX_INFO_ASYNC(root, L"Some wide string " << 42);
#else
			LOG4CXX_INFO_ASYNC(root, "Some narrow string " << 42);
#endif
#endif // LOG4CXX_XXXX_ASYNC_MACROS_WORK_WITH_ANY_CHAR_TYPE

			// Check all messages were received
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(expectedMessageCount, int(v.size()));
		}

		// this test checks all messages are delivered when an AsyncAppender is closed
		void testEventFlush()
		{
			// Configure Log4cxx
			auto r = LogManager::getLoggerRepository();
			AsyncAppenderPtr asyncAppender;
			r->ensureIsConfigured([r, &asyncAppender]()
			{
				asyncAppender = std::make_shared<AsyncAppender>();
				asyncAppender->setName(LOG4CXX_STR("async-testEventFlush"));
				r->getRootLogger()->addAppender(asyncAppender);
				r->setConfigured(true);
			});
			LOGUNIT_ASSERT(asyncAppender);
			auto vectorAppender = std::make_shared<VectorAppender>();
			vectorAppender->setMillisecondDelay(1);
			asyncAppender->addAppender(vectorAppender);

			// Log some messages
			auto root = r->getRootLogger();
			size_t LEN = 200; // Larger than default buffer size (128)
			for (size_t i = 0; i < LEN; i++)
			{
				LOG4CXX_DEBUG_ASYNC(root, "message" << i);
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
				LOGUNIT_ASSERT(v[i]->getRenderedMessage() == m);
			}
			LOGUNIT_ASSERT_EQUAL(true, vectorAppender->isClosed());
		}


		// this test checks all messages are delivered from multiple threads
		void testMultiThread()
		{
			// Configure Log4cxx
			AsyncAppenderPtr asyncAppender;
			auto r = LogManager::getLoggerRepository();
			r->ensureIsConfigured([r, &asyncAppender]()
			{
				asyncAppender = std::make_shared<AsyncAppender>();
				asyncAppender->setName(LOG4CXX_STR("async-testMultiThread"));
				r->getRootLogger()->addAppender(asyncAppender);
				r->setConfigured(true);
			});
			LOGUNIT_ASSERT(asyncAppender);
			auto vectorAppender = std::make_shared<VectorAppender>();
			asyncAppender->addAppender(vectorAppender);

			// Log some messages
			int LEN = 2000; // Larger than default buffer size (128)
			auto threadCount = std::max(static_cast<int>(std::thread::hardware_concurrency() - 1), 2);
			auto root = r->getRootLogger();
			std::vector<std::thread> threads;
			for ( int x = 0; x < threadCount; x++ )
			{
				threads.emplace_back([root, LEN]()
				{
					for (int i = 0; i < LEN; i++)
					{
						LOG4CXX_DEBUG_ASYNC(root, "message" << i);
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

			// Check all message were received
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(LEN*threadCount, (int)v.size());
			std::map<LogString, int> perThreadCount;
			std::vector<int> msgCount(LEN, 0);
			for (auto m : v)
			{
				auto i = StringHelper::toInt(m->getRenderedMessage().substr(7));
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
			// Configure Log4cxx
			AsyncAppenderPtr asyncAppender;
			auto r = LogManager::getLoggerRepository();
			r->ensureIsConfigured([r, &asyncAppender]()
			{
				asyncAppender = std::make_shared<AsyncAppender>();
				asyncAppender->setName(LOG4CXX_STR("async-testBadAppender"));
				asyncAppender->addAppender(std::make_shared<NullPointerAppender>());
				Pool p;
				asyncAppender->activateOptions(p);
				r->getRootLogger()->addAppender(asyncAppender);
				r->setConfigured(true);
			});
			LOGUNIT_ASSERT(asyncAppender);
			auto vectorAppender = std::make_shared<VectorAppender>();
			vectorAppender->setName(LOG4CXX_STR("async-memoryAppender"));
			auto root = r->getRootLogger();
			auto errorHandler = std::make_shared<varia::FallbackErrorHandler>();
			errorHandler->setAppender(asyncAppender);
			errorHandler->setBackupAppender(vectorAppender);
			errorHandler->setLogger(root);
			asyncAppender->setErrorHandler(errorHandler);

			// Log some messages
			LOG4CXX_INFO(root, "Message");
			std::this_thread::sleep_for( std::chrono::milliseconds( 30 ) );
			LOGUNIT_ASSERT(errorHandler->errorReported());
			LOG4CXX_INFO(root, "Message");

			// Check a message was received
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT(0 < v.size());
		}

		/**
		 * Tests behavior when the the async buffer overflows.
		 */
		void testBufferOverflowBehavior()
		{
			// Configure Log4cxx
			AsyncAppenderPtr async;
			auto r = LogManager::getLoggerRepository();
			r->ensureIsConfigured([r, &async]()
			{
				async = std::make_shared<AsyncAppender>();
				async->setName(LOG4CXX_STR("async-testBufferOverflowBehavior"));
				async->setBufferSize(5);
				async->setBlocking(false);
				Pool p;
				async->activateOptions(p);
				r->getRootLogger()->addAppender(async);
				r->setConfigured(true);
			});
			LOGUNIT_ASSERT(async);
			auto blockableAppender = std::make_shared<BlockableVectorAppender>();
			blockableAppender->setName(LOG4CXX_STR("async-blockableVector"));
			async->addAppender(blockableAppender);

			// Log some messages
			auto rootLogger = r->getRootLogger();
			LOG4CXX_INFO_ASYNC(rootLogger, "Hello, World"); // This causes the dispatch thread creation
			std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) ); // Wait for the dispatch thread  to be ready
			{
				std::lock_guard<std::mutex> sync(blockableAppender->getBlocker());

				for (int i = 0; i < 140; i++)
				{
					LOG4CXX_INFO_ASYNC(rootLogger, "Hello, World " << i);
				}

				LOG4CXX_ERROR_ASYNC(rootLogger, "That's all folks.");
			}
			async->close();

			// Check which messages were output
			auto& events = blockableAppender->getVector();
			LOGUNIT_ASSERT(!events.empty());
			LOGUNIT_ASSERT(events.size() <= 142);
			LoggingEventPtr initialEvent = events.front();
			LOGUNIT_ASSERT(initialEvent->getRenderedMessage() == LOG4CXX_STR("Hello, World"));
			std::map<LevelPtr, int> levelCount;
			int discardMessageCount{ 0 };
			LoggingEventPtr discardEvent;
			for (auto& e : events)
			{
				++levelCount[e->getLevel()];
				if (e->getRenderedMessage().substr(0, 10) == LOG4CXX_STR("Discarded "))
				{
					++discardMessageCount;
					discardEvent = e;
				}
			}
			if (helpers::LogLog::isDebugEnabled())
			{
				Pool p;
				LogString msg{ LOG4CXX_STR("messageCounts:") };
				for (auto& item : levelCount)
				{
					msg += LOG4CXX_STR(" ");
					msg += item.first->toString();
					msg += LOG4CXX_STR(" ");
					StringHelper::toString(item.second, p, msg);
				}
				msg += LOG4CXX_STR(" ");
				msg += LOG4CXX_STR("Discarded ");
				StringHelper::toString(discardMessageCount, p, msg);
				helpers::LogLog::debug(msg);
			}
			// Check this test has activated the discard logic
			LOGUNIT_ASSERT(1 <= discardMessageCount);
			LOGUNIT_ASSERT(5 < levelCount[Level::getInfo()]);
			// Check the discard message is the logging event of the highest level
			LOGUNIT_ASSERT_EQUAL(levelCount[Level::getError()], 1);
			LOGUNIT_ASSERT_EQUAL(discardEvent->getLevel(), Level::getError());
			// Check the discard message does not have location info
			LOGUNIT_ASSERT_EQUAL(log4cxx::spi::LocationInfo::getLocationUnavailable().getClassName(),
				discardEvent->getLocationInformation().getClassName());
		}

		/**
		 * Tests behavior when the appender attached to a AsyncAppender adds logging events
		 */
		void testLoggingAppender()
		{
			// Configure Log4cxx
			AsyncAppenderPtr async;
			auto r = LogManager::getLoggerRepository();
			r->ensureIsConfigured([r, &async]()
			{
				async = std::make_shared<AsyncAppender>();
				async->setName(LOG4CXX_STR("withLoggingAppender"));
				async->setBufferSize(5);
				Pool p;
				async->activateOptions(p);
				r->getRootLogger()->addAppender(async);
				r->setConfigured(true);
			});
			LOGUNIT_ASSERT(async);
			auto loggingAppender = std::make_shared<LoggingVectorAppender>();
			loggingAppender->setName(LOG4CXX_STR("loggingAppender"));
			async->addAppender(loggingAppender);

			// Log some messages
			auto rootLogger = r->getRootLogger();
			LOG4CXX_INFO_ASYNC(rootLogger, "Hello, World"); // This causes the dispatch thread creation
			std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) ); // Wait for the dispatch thread  to be ready
			for (int i = 0; i < 10; i++)
			{
				LOG4CXX_INFO_ASYNC(rootLogger, "Hello, World " << i);
			}
			LOG4CXX_INFO_ASYNC(rootLogger, "Bye bye World");
			std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) ); // Wait for the dispatch thread take the above events
			async->close();

			// Check which messages were received
			auto& events = loggingAppender->getVector();
			std::map<LevelPtr, int> levelCount;
			int discardMessageCount{ 0 };
			int eventCount[] = { 0, 0 };
			for (auto& e : events)
			{
				++levelCount[e->getLevel()];
				auto message = e->getRenderedMessage();
				LogLog::debug(message);
				auto isAppenderMessage = (message.npos == message.find(LOG4CXX_STR("World")));
				++eventCount[isAppenderMessage];
				if (message.substr(0, 10) == LOG4CXX_STR("Discarded "))
				{
					++discardMessageCount;
					LOGUNIT_ASSERT(isAppenderMessage);
				}
			}
			if (helpers::LogLog::isDebugEnabled())
			{
				Pool p;
				LogString msg{ LOG4CXX_STR("messageCounts:") };
				msg += LOG4CXX_STR(" nonAppender ");
				StringHelper::toString(eventCount[0], p, msg);
				msg += LOG4CXX_STR(" appender ");
				StringHelper::toString(eventCount[1], p, msg);
				msg += LOG4CXX_STR(" discard ");
				StringHelper::toString(discardMessageCount, p, msg);
				LogLog::debug(msg);
			}
			LOGUNIT_ASSERT(12 < events.size());
			// A race condition in AsyncAppender can result in a lost message when the dispatch thread is logging events
			LOGUNIT_ASSERT(10 <= eventCount[0]);
		}

#if LOG4CXX_HAS_DOMCONFIGURATOR
		void testXMLConfiguration()
		{
			// Configure Log4cxx
			auto status = xml::DOMConfigurator::configure("input/xml/asyncAppender1.xml");
			LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);

			// Check configuration is as expected
			auto  root = Logger::getRootLogger();
			auto asyncAppender = log4cxx::cast<AsyncAppender>(root->getAppender(LOG4CXX_STR("ASYNC")));
			LOGUNIT_ASSERT(asyncAppender);
			LOGUNIT_ASSERT_EQUAL(100, asyncAppender->getBufferSize());
			LOGUNIT_ASSERT_EQUAL(false, asyncAppender->getBlocking());
			LOGUNIT_ASSERT_EQUAL(true, asyncAppender->getLocationInfo());
			auto nestedAppenders = asyncAppender->getAllAppenders();
			LOGUNIT_ASSERT_EQUAL(1, int(nestedAppenders.size()));

			// Log some messages
			size_t LEN = 20;
			for (size_t i = 0; i < LEN; i++)
			{
				LOG4CXX_DEBUG_ASYNC(root, "message" << i);
			}
			asyncAppender->close();

			// Check all message were received
			auto vectorAppender = log4cxx::cast<VectorAppender>(asyncAppender->getAppender(LOG4CXX_STR("VECTOR")));
			LOGUNIT_ASSERT(vectorAppender);
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(LEN, v.size());
			LOGUNIT_ASSERT(vectorAppender->isClosed());
		}

		void testAsyncLoggerXML()
		{
			// Configure Log4cxx
			auto status = xml::DOMConfigurator::configure("input/xml/asyncLogger.xml");
			LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);

			// Check configuration is as expected
			auto  root = Logger::getRootLogger();
			auto appenders = root->getAllAppenders();
			LOGUNIT_ASSERT_EQUAL(1, int(appenders.size()));
			auto asyncAppender = log4cxx::cast<AsyncAppender>(appenders.front());
			LOGUNIT_ASSERT(asyncAppender);

			// Log some messages
			size_t LEN = 20;
			for (size_t i = 0; i < LEN; i++)
			{
				LOG4CXX_INFO_ASYNC(root, "message" << i);
			}
			asyncAppender->close();

			// Check all message were received
			auto vectorAppender = log4cxx::cast<VectorAppender>(asyncAppender->getAppender(LOG4CXX_STR("VECTOR")));
			LOGUNIT_ASSERT(vectorAppender);
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(LEN, v.size());
			LOGUNIT_ASSERT(vectorAppender->isClosed());
		}
#endif

		void testAsyncLoggerProperties()
		{
			// Configure Log4cxx
			auto status = PropertyConfigurator::configure("input/asyncLogger.properties");
			LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);

			// Check configuration is as expected
			auto  root = Logger::getRootLogger();
			auto appenders = root->getAllAppenders();
			LOGUNIT_ASSERT_EQUAL(1, int(appenders.size()));
			auto asyncAppender = log4cxx::cast<AsyncAppender>(appenders.front());
			LOGUNIT_ASSERT(asyncAppender);

			// Log some messages
			size_t LEN = 20;
			for (size_t i = 0; i < LEN; i++)
			{
				LOG4CXX_INFO_ASYNC(root, "message" << i);
			}
			asyncAppender->close();

			// Check all message were received
			auto vectorAppender = log4cxx::cast<VectorAppender>(asyncAppender->getAppender(LOG4CXX_STR("VECTOR")));
			LOGUNIT_ASSERT(vectorAppender);
			auto& v = vectorAppender->getVector();
			LOGUNIT_ASSERT_EQUAL(LEN, v.size());
			LOGUNIT_ASSERT(vectorAppender->isClosed());
		}


};

LOGUNIT_TEST_SUITE_REGISTRATION(AsyncAppenderTestCase);
