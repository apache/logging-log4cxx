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

#include <log4cxx/varia/fallbackerrorhandler.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/logmanager.h>
#if LOG4CXX_ABI_VERSION <= 15
#include <log4cxx/logger.h>
#include <log4cxx/asyncappender.h>
#endif
#include <list>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::varia;

IMPLEMENT_LOG4CXX_OBJECT(FallbackErrorHandler)

struct FallbackErrorHandler::FallbackErrorHandlerPrivate
{
	std::list<AppenderPtr> backup;
	AppenderWeakPtr primary;
	std::map<LogString, spi::AppenderAttachableWeakPtr> appenderHolders;
	bool errorReported = false;
};

FallbackErrorHandler::FallbackErrorHandler()
	: m_priv(std::make_unique<FallbackErrorHandlerPrivate>())
{
}

FallbackErrorHandler::~FallbackErrorHandler() {}

void FallbackErrorHandler::addAppenderHolder(const LogString& name, const spi::AppenderAttachablePtr& clx)
{
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(((LogString) LOG4CXX_STR("FB: Adding appender holder ["))
			+ name + LOG4CXX_STR("]."));
	}
	m_priv->appenderHolders.emplace(name, clx);
}

void FallbackErrorHandler::setLogger(const LoggerPtr& logger)
{
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(((LogString) LOG4CXX_STR("FB: Adding logger ["))
			+ logger->getName() + LOG4CXX_STR("]."));
	}
	m_priv->appenderHolders.emplace(logger->getName(), logger);
}

void FallbackErrorHandler::error(const LogString& message) const
{
	LogLog::warn(message);
	m_priv->errorReported = true;
}

void FallbackErrorHandler::error
	( const LogString& message
	, const std::exception& ex
	, int errorCode
	) const
{
	error(message, ex, errorCode, 0);
}

void FallbackErrorHandler::error
	( const LogString& message
	, const std::exception& ex
	, int errorCode
	, const spi::LoggingEventPtr& event
	) const
{
	if (LogLog::isDebugEnabled())
	{
		LogString msg{ LOG4CXX_STR("FB: error code ") };
		StringHelper::toString(errorCode, msg);
		LogLog::debug(msg);
	}
	LogLog::warn(message, ex);

	AppenderPtr primaryLocked = m_priv->primary.lock();
	AppenderPtr backupLocked;
	if (!m_priv->backup.empty())
	{
		backupLocked = m_priv->backup.front();
		m_priv->backup.pop_front();
	}

	if ( !primaryLocked || !backupLocked )
	{
		return;
	}

	for (auto& item : m_priv->appenderHolders)
	{
		auto holderLocked = item.second.lock();
		if (!holderLocked)
			continue;
		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("FB: Replacing [")
				+ primaryLocked->getName() + LOG4CXX_STR("] with [")
				+ backupLocked->getName() + LOG4CXX_STR("] in [")
				+ item.first + LOG4CXX_STR("]."));
		}
#if LOG4CXX_ABI_VERSION <= 15
		bool ok{ false };
		if (auto logger = LOG4CXX_NS::cast<Logger>(holderLocked))
			ok = logger->replaceAppender(primaryLocked, backupLocked);
		else if (auto asyncAppender = LOG4CXX_NS::cast<AsyncAppender>(holderLocked))
			ok = asyncAppender->replaceAppender(primaryLocked, backupLocked);
		if (!ok)
#else
		if (!holderLocked->replaceAppender(primaryLocked, backupLocked))
#endif
		{
			LogLog::debug(LOG4CXX_STR("FB: Failed to replace [")
				+ primaryLocked->getName() + LOG4CXX_STR("] with [")
				+ backupLocked->getName() + LOG4CXX_STR("] in [")
				+ item.first + LOG4CXX_STR("]."));
		}
	}
	m_priv->errorReported = true;
	if (event)
    {
        Pool p;
		backupLocked->doAppend(event, p);
    }
	m_priv->primary = backupLocked;
}

void FallbackErrorHandler::setAppender(const AppenderPtr& primary1)
{
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(((LogString) LOG4CXX_STR("FB: Setting primary appender to ["))
			+ primary1->getName() + LOG4CXX_STR("]."));
	}
	m_priv->primary = primary1;
}

void FallbackErrorHandler::setBackupAppender(const AppenderPtr& backup1)
{
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(((LogString) LOG4CXX_STR("FB: Setting backup appender to ["))
			+ backup1->getName() + LOG4CXX_STR("]."));
	}
	m_priv->backup.push_back(backup1);
}

#if LOG4CXX_ABI_VERSION <= 15
void FallbackErrorHandler::activateOptions(Pool&)
{
}
#endif

void FallbackErrorHandler::setOption(const LogString&, const LogString&)
{
}

bool FallbackErrorHandler::errorReported() const
{
	return m_priv->errorReported;
}
