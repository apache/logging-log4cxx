
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

#include <log4cxx/levelchange.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/loglog.h>
#include "logunit.h"

using namespace log4cxx;

namespace
{

class CountingAppender : public AppenderSkeleton
{
	public:
		int count;

		CountingAppender() : count(0)
		{}

		void close() override
		{}

		void append(const spi::LoggingEventPtr& /*event*/, helpers::Pool& /*p*/) override
		{
			count++;
		}

		bool requiresLayout() const override
		{
			return true;
		}

		LogString getName() const override
		{
			return LOG4CXX_STR("counter");
		}
};

LoggerPtr getLogger(const LogString& name = LogString())
{
	auto r = LogManager::getLoggerRepository();
	r->ensureIsConfigured([r]()
		{
			r->getRootLogger()->addAppender(std::make_shared<CountingAppender>());
		});
	return name.empty() ? r->getRootLogger() : r->getLogger(name);
}

} // anonymous namespace

// A mocked worker
class ComplexProcessing
{
public:
	LoggerPtr logger = getLogger(LOG4CXX_STR("ComplexProcessing"));
	void DoStep1()
	{
		LOG4CXX_DEBUG(logger, "Step 1 message");
	}
	void DoStep2()
	{
		LOG4CXX_DEBUG(logger, "Step 2 message");
	}
	void DoStep3()
	{
		LOG4CXX_DEBUG(logger, "Step 3 message");
	}
};
static ComplexProcessing processor;

LOGUNIT_CLASS(LevelChangeTestCase)
{
	LOGUNIT_TEST_SUITE(LevelChangeTestCase);
	LOGUNIT_TEST(testLevelChange);
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
		// Disable DEBUG output from ComplexProcessing
		processor.logger->setLevel(Level::getInfo());
	}

	void testLevelChange()
	{
		auto appender = dynamic_cast<CountingAppender*>(getLogger()->getAppender(LOG4CXX_STR("counter")).get());
		LOGUNIT_ASSERT(appender);

		auto myLogger = getLogger(LOG4CXX_STR("Controller"));
		myLogger->setLevel(Level::getDebug());

		// Check this debug request is sent to the appender
		LOG4CXX_DEBUG(myLogger, "Start test");
		auto initialCount = appender->count;
		LOGUNIT_ASSERT_EQUAL(initialCount, 1);

		// Check the ComplexProcessing debug request is not sent to the appender
		processor.DoStep1();
		LOGUNIT_ASSERT_EQUAL(appender->count, initialCount);
		{
			LevelChange ctx(getLogger(LOG4CXX_STR("ComplexProcessing")), myLogger);
			processor.DoStep2();
			// Check the ComplexProcessing debug request was sent to the appender
			LOGUNIT_ASSERT_EQUAL(appender->count, initialCount + 1);
		}

		// Check the ComplexProcessing debug request is not sent to the appender
		processor.DoStep1();
		LOGUNIT_ASSERT_EQUAL(appender->count, initialCount + 1);
		{
			LevelChange ctx(LOG4CXX_STR("ComplexProcessing"), myLogger);
			processor.DoStep2();
			// Check the ComplexProcessing debug request was sent to the appender
			LOGUNIT_ASSERT_EQUAL(appender->count, initialCount + 2);
		}

		// Check the ComplexProcessing debug request is no longer sent to the appender
		auto finalCount = appender->count;
		processor.DoStep3();
		LOGUNIT_ASSERT_EQUAL(appender->count, finalCount);
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(LevelChangeTestCase);
