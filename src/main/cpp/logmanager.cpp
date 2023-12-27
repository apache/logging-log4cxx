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

#include <log4cxx/logmanager.h>
#include <log4cxx/defaultconfigurator.h>
#include <log4cxx/spi/defaultrepositoryselector.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/spi/rootlogger.h>
#include <log4cxx/spi/loggerfactory.h>
#include <stdexcept>
#include <log4cxx/level.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/loglog.h>

#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/file.h>
#include <log4cxx/helpers/transcoder.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/helpers/aprinitializer.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(DefaultRepositorySelector)

void* LogManager::guard = 0;

RepositorySelectorPtr LogManager::getRepositorySelector()
{
	auto result = APRInitializer::getOrAddUnique<spi::RepositorySelector>( []() -> ObjectPtr
		{
			LoggerRepositoryPtr hierarchy = Hierarchy::create();
			return std::make_shared<DefaultRepositorySelector>(hierarchy);
		}
	);
	return result;
}

void LogManager::setRepositorySelector(spi::RepositorySelectorPtr selector, void* guard1)
{
	if ((LogManager::guard != 0) && (LogManager::guard != guard1))
	{
		throw IllegalArgumentException(LOG4CXX_STR("Attempted to reset the LoggerFactory without possessing the guard."));
	}

	if (selector == 0)
	{
		throw IllegalArgumentException(LOG4CXX_STR("RepositorySelector must be non-null."));
	}

	LogManager::guard = guard1;
	APRInitializer::setUnique<spi::RepositorySelector>(selector);
}



LoggerRepositoryPtr LogManager::getLoggerRepository()
{
	return getRepositorySelector()->getLoggerRepository();
}

LoggerPtr LogManager::getRootLogger()
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	auto r = getLoggerRepository();
	r->ensureIsConfigured(std::bind(DefaultConfigurator::configure, r));
	return r->getRootLogger();
}

/**
Retrieve the appropriate Logger instance.
*/
LoggerPtr LogManager::getLoggerLS(const LogString& name)
{
	auto r = getLoggerRepository();
	r->ensureIsConfigured(std::bind(DefaultConfigurator::configure, r));
	return r->getLogger(name);
}

/**
Retrieve the appropriate Logger instance.
*/
LoggerPtr LogManager::getLoggerLS(const LogString& name,
	const spi::LoggerFactoryPtr& factory)
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	auto r = getLoggerRepository();
	r->ensureIsConfigured(std::bind(DefaultConfigurator::configure, r));
	return r->getLogger(name, factory);
}

LoggerPtr LogManager::getLogger(const std::string& name)
{
	LOG4CXX_DECODE_CHAR(n, name);
	return getLoggerLS(n);
}

LoggerPtr LogManager::getLogger(const std::string& name,
	const spi::LoggerFactoryPtr& factory)
{
	LOG4CXX_DECODE_CHAR(n, name);
	return getLoggerLS(n, factory);
}

LoggerPtr LogManager::exists(const std::string& name)
{
	LOG4CXX_DECODE_CHAR(n, name);
	return existsLS(n);
}

#if LOG4CXX_WCHAR_T_API
LoggerPtr LogManager::getLogger(const std::wstring& name)
{
	LOG4CXX_DECODE_WCHAR(n, name);
	return getLoggerLS(n);
}

LoggerPtr LogManager::getLogger(const std::wstring& name,
	const spi::LoggerFactoryPtr& factory)
{
	LOG4CXX_DECODE_WCHAR(n, name);
	return getLoggerLS(n, factory);
}

LoggerPtr LogManager::exists(const std::wstring& name)
{
	LOG4CXX_DECODE_WCHAR(n, name);
	return existsLS(n);
}
#endif

#if LOG4CXX_UNICHAR_API
LoggerPtr LogManager::getLogger(const std::basic_string<UniChar>& name)
{
	LOG4CXX_DECODE_UNICHAR(n, name);
	return getLoggerLS(n);
}

LoggerPtr LogManager::getLogger(const std::basic_string<UniChar>& name,
	const spi::LoggerFactoryPtr& factory)
{
	LOG4CXX_DECODE_UNICHAR(n, name);
	return getLoggerLS(n, factory);
}

LoggerPtr LogManager::exists(const std::basic_string<UniChar>& name)
{
	LOG4CXX_DECODE_UNICHAR(n, name);
	return existsLS(n);
}
#endif

#if LOG4CXX_CFSTRING_API
LoggerPtr LogManager::getLogger(const CFStringRef& name)
{
	LOG4CXX_DECODE_CFSTRING(n, name);
	return getLoggerLS(n);
}

LoggerPtr LogManager::getLogger(const CFStringRef& name,
	const spi::LoggerFactoryPtr& factory)
{
	LOG4CXX_DECODE_CFSTRING(n, name);
	return getLoggerLS(n, factory);
}

LoggerPtr LogManager::exists(const CFStringRef& name)
{
	LOG4CXX_DECODE_CFSTRING(n, name);
	return existsLS(n);
}
#endif

LoggerPtr LogManager::existsLS(const LogString& name)
{
	return getLoggerRepository()->exists(name);
}

LoggerList LogManager::getCurrentLoggers()
{
	return getLoggerRepository()->getCurrentLoggers();
}

void LogManager::shutdown()
{
	APRInitializer::unregisterAll();
	getLoggerRepository()->shutdown();
}

void LogManager::resetConfiguration()
{
	getLoggerRepository()->resetConfiguration();
}

bool LogManager::removeLogger(const LogString& name, bool ifNotUsed)
{
#if LOG4CXX_ABI_VERSION <= 15
	bool result = false;
	if (auto r = dynamic_cast<Hierarchy*>(getLoggerRepository().get()))
		result = r->removeLogger(name, ifNotUsed);
	return result;
#else
	return getLoggerRepository()->removeLogger(name, ifNotUsed);
#endif
}
