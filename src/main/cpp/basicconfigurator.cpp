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
#include <log4cxx/logstring.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/asyncappender.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/loglog.h>

using namespace LOG4CXX_NS;

namespace
{

LayoutPtr getDefaultLayout()
{
	auto pattern = LogString
		{ helpers::LogLog::isColorEnabled()
		? LOG4CXX_STR("%r [%t] %p %c %x - %Y%m%y%n")
		: LOG4CXX_STR("%r [%t] %p %c %x - %m%n")
		};
	return std::make_shared<PatternLayout>(pattern);
}

} // namespace


void BasicConfigurator::configure(const LayoutPtr& layoutArg)
{
	auto appender = std::make_shared<ConsoleAppender>(layoutArg ? layoutArg : getDefaultLayout());
	appender->setName(LOG4CXX_STR("BasicConfigurator"));
	auto r = LogManager::getLoggerRepository();
	r->getRootLogger()->addAppender(appender);
	r->setConfigured(true);
}

void BasicConfigurator::configure(const AppenderPtr& appender)
{
	auto r = LogManager::getLoggerRepository();
	r->getRootLogger()->addAppender(appender);
	r->setConfigured(true);
}

void BasicConfigurator::configureAsync(const LayoutPtr& layoutArg)
{
	auto ringBuffer = std::make_shared<AsyncAppender>();
	ringBuffer->setName(LOG4CXX_STR("Default"));
	ringBuffer->addAppender(std::make_shared<ConsoleAppender>(layoutArg ? layoutArg : getDefaultLayout()));
	auto r = LogManager::getLoggerRepository();
	r->getRootLogger()->addAppender(ringBuffer);
	r->setConfigured(true);
}

void BasicConfigurator::configureAsync(const AppenderPtr& appender)
{
	auto ringBuffer = std::make_shared<AsyncAppender>();
	ringBuffer->addAppender(appender);
	ringBuffer->setName(LOG4CXX_STR("Default"));
	auto r = LogManager::getLoggerRepository();
	r->getRootLogger()->addAppender(ringBuffer);
	r->setConfigured(true);
}

void BasicConfigurator::resetConfiguration()
{
	LogManager::resetConfiguration();
}
