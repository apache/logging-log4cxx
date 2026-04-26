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
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;

/**
 * Tests activateOptions in ABI 15 and 16.
 *
 */

class ABI_15_Appender : public AppenderSkeleton
{
public:
	void close() override
	{}

	void append(const spi::LoggingEventPtr& /*event*/, helpers::Pool& /*p*/) override
	{
		helpers::LogLog::debug(LOG4CXX_STR("ABI_15_Appender::append"));
	}

	bool requiresLayout() const override
	{
		return false;
	}

	void activateOptions(helpers::Pool& p)
	{
		helpers::LogLog::debug(LOG4CXX_STR("ABI_15_Appender::activateOptions"));
		AppenderSkeleton::activateOptions(p);
		m_activated = true;
	}

	bool isActivated() const
	{
		return m_activated;
	}
private:
	bool m_activated{ false };
};


class BaseAppender : public AppenderSkeleton
{
public:
	void close() override
	{}

	void append(const spi::LoggingEventPtr& /*event*/, helpers::Pool& /*p*/) override
	{
		helpers::LogLog::debug(LOG4CXX_STR("BaseAppender::append"));
	}

	bool requiresLayout() const override
	{
		return false;
	}

	using AppenderSkeleton::activateOptions;
	void activateOptions( LOG4CXX_ACTIVATE_OPTIONS_FORMAL_PARAMETERS ) override
	{
		helpers::LogLog::debug(LOG4CXX_STR("BaseAppender::activateOptions"));
		AppenderSkeleton::activateOptions( LOG4CXX_ACTIVATE_OPTIONS_PARAMETER );
		m_activated = true;
	}

	bool isActivated() const
	{
		return m_activated;
	}
private:
	bool m_activated{ false };
};

class ABI_15_Specialized_Appender : public BaseAppender
{
public:
	// void activateOptions(helpers::Pool& p) override --> compiler error: 'ABI_15_Specialized_Appender::activateOptions': method with override specifier 'override' did not override any base class methods
	//                                                                     'log4cxx::spi::OptionHandler::activateOptions': Use activateOptions() without parameters instead
	void activateOptions(helpers::Pool& p)
	{
		helpers::LogLog::debug(LOG4CXX_STR("ABI_15_Specialized_Appender::activateOptions"));
		BaseAppender::activateOptions(p); // --> compiler warning: 'log4cxx::spi::OptionHandler::activateOptions': Use activateOptions() without parameters instead
		m_activated = true;
	}

	bool isActivated() const
	{
		return BaseAppender::isActivated() && m_activated;
	}
private:
	bool m_activated{ false };
};

#if 15 < LOG4CXX_ABI_VERSION
class ABI_16_Appender : public BaseAppender
{
public:
	void activateOptions() override
	{
		helpers::LogLog::debug(LOG4CXX_STR("ABI_16_Appender::activateOptions"));
		BaseAppender::activateOptions();
		m_activated = true;
	}

	bool isActivated() const
	{
		return BaseAppender::isActivated() && m_activated;
	}
private:
	bool m_activated{ false };
};

#endif

LOGUNIT_CLASS(OptionHandlerTest)
{
	LOGUNIT_TEST_SUITE(OptionHandlerTest);
	LOGUNIT_TEST(ABI_15_AppenderTest);
	LOGUNIT_TEST(ABI_15_Specialized_AppenderTest);
#if 15 < LOG4CXX_ABI_VERSION
	LOGUNIT_TEST(ABI_16_AppenderTest);
#endif
	LOGUNIT_TEST_SUITE_END();
public:

	/**
	 * Checks a simple user defined ABI 15 style appender still works
	 */
	void ABI_15_AppenderTest()
	{
		helpers::Pool p;
		ABI_15_Appender a15;
		a15.activateOptions(p);
		LOGUNIT_ASSERT(a15.isActivated());
	}

	/**
	 * Checks all levels of the appender heirarchy are activated
	 */
	void ABI_15_Specialized_AppenderTest()
	{
		helpers::Pool p;
		ABI_15_Specialized_Appender a15s;
		a15s.activateOptions(p);
		LOGUNIT_ASSERT(a15s.isActivated());
	}

#if 15 < LOG4CXX_ABI_VERSION
	/**
	 * Checks all levels of the appender heirarchy are activated
	 */
	void ABI_16_AppenderTest()
	{
		ABI_16_Appender a16;
		a16.activateOptions();
		LOGUNIT_ASSERT(a16.isActivated());
	}
#endif

};

LOGUNIT_TEST_SUITE_REGISTRATION(OptionHandlerTest);

