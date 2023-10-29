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

#include <log4cxx/appender.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/onlyonceerrorhandler.h>
#include <log4cxx/helpers/loglog.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

IMPLEMENT_LOG4CXX_OBJECT(OnlyOnceErrorHandler)

struct OnlyOnceErrorHandler::OnlyOnceErrorHandlerPrivate{
	OnlyOnceErrorHandlerPrivate() :
		WARN_PREFIX(LOG4CXX_STR("log4cxx warning: ")),
		ERROR_PREFIX(LOG4CXX_STR("log4cxx error: ")),
		firstTime(true){}

	LogString WARN_PREFIX;
	LogString ERROR_PREFIX;
	mutable bool firstTime;
};

OnlyOnceErrorHandler::OnlyOnceErrorHandler() :
	m_priv(std::make_unique<OnlyOnceErrorHandlerPrivate>())
{
}

OnlyOnceErrorHandler::~OnlyOnceErrorHandler(){}

void OnlyOnceErrorHandler::setLogger(const LoggerPtr&)
{
}

void OnlyOnceErrorHandler::activateOptions(Pool&)
{
}

void OnlyOnceErrorHandler::setOption(const LogString&, const LogString&)
{
}

void OnlyOnceErrorHandler::error(const LogString& message, const std::exception& e,
	int) const
{
	if (m_priv->firstTime)
	{
		LogLog::error(message, e);
		m_priv->firstTime = false;
	}
}

void OnlyOnceErrorHandler::error(const LogString& message, const std::exception& e,
	int errorCode, const LOG4CXX_NS::spi::LoggingEventPtr&) const
{
	error(message, e, errorCode);
}


void OnlyOnceErrorHandler::error(const LogString& message) const
{
	if (m_priv->firstTime)
	{
		LogLog::error(message);
		m_priv->firstTime = false;
	}
}


void OnlyOnceErrorHandler::setAppender(const AppenderPtr&)
{
}


void OnlyOnceErrorHandler::setBackupAppender(const AppenderPtr&)
{
}
