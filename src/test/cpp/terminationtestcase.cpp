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
#include "vectorappender.h"
#include <log4cxx/asyncappender.h>
#include <thread>

using namespace log4cxx;

static VectorAppenderPtr vectorAppender = std::make_shared<VectorAppender>();

LOGUNIT_CLASS(TerminationTestCase)
{
	LOGUNIT_TEST_SUITE(TerminationTestCase);
	LOGUNIT_TEST(logOnce);
	LOGUNIT_TEST_SUITE_END();

public:

	static void setDefaultAppender()
	{
		auto r = LogManager::getLoggerRepository();
		r->ensureIsConfigured([r]()
			{
			auto asyncAppender = std::make_shared<AsyncAppender>();
			asyncAppender->addAppender(vectorAppender);
			r->getRootLogger()->addAppender(asyncAppender);
			}
		);
	}

	static LoggerPtr getLogger(const LogString& name = LogString())
	{
		static struct initializer
		{
			initializer() { setDefaultAppender(); }
#if !LOG4CXX_EVENTS_AT_EXIT
			~initializer() { LogManager::shutdown(); }
#endif
		} x;
		auto r = LogManager::getLoggerRepository();
		return name.empty() ? r->getLogger(name) : r->getRootLogger();
	}

	void logOnce()
	{
		auto root = getLogger();
		LOG4CXX_INFO(root, "Message");
		std::this_thread::sleep_for( std::chrono::milliseconds( 30 ) );
		const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
		LOGUNIT_ASSERT_EQUAL((size_t) 1, v.size());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(TerminationTestCase);
