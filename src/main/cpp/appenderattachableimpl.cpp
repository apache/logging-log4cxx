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
#include <log4cxx/helpers/appenderattachableimpl.h>
#include <log4cxx/appender.h>
#include <log4cxx/spi/loggingevent.h>
#include <algorithm>
#include <log4cxx/helpers/pool.h>
#include <mutex>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(AppenderAttachableImpl)

struct AppenderAttachableImpl::priv_data
{
	/** Array of appenders. */
	AppenderList  appenderList;
	mutable std::recursive_mutex m_mutex;
};


AppenderAttachableImpl::AppenderAttachableImpl(Pool& pool) :
	m_priv(std::make_unique<AppenderAttachableImpl::priv_data>())
{
}

AppenderAttachableImpl::~AppenderAttachableImpl()
{

}

void AppenderAttachableImpl::addAppender(const AppenderPtr newAppender)
{
	// Null values for newAppender parameter are strictly forbidden.
	if (newAppender == 0)
	{
		return;
	}

	std::lock_guard<std::recursive_mutex> lock( m_priv->m_mutex );
	auto it = std::find(m_priv->appenderList.begin(), m_priv->appenderList.end(), newAppender);
	if (it == m_priv->appenderList.end())
	{
		m_priv->appenderList.push_back(newAppender);
	}
}

int AppenderAttachableImpl::appendLoopOnAppenders(
	const spi::LoggingEventPtr& event,
	Pool& p)
{
	int numberAppended = 0;
	// FallbackErrorHandler::error() may modify our list of appenders
	// while we are iterating over them (if it holds the same logger).
	// So, make a local copy of the appenders that we want to iterate over
	// before actually iterating over them.
	// doAppend() will serialize calls to AppenderSkeleton#append.
	for (auto appender : getAllAppenders())
	{
		appender->doAppend(event, p);
		numberAppended++;
	}

	return numberAppended;
}

AppenderList AppenderAttachableImpl::getAllAppenders() const
{
	std::lock_guard<std::recursive_mutex> lock( m_priv->m_mutex );
	return m_priv->appenderList;
}

AppenderPtr AppenderAttachableImpl::getAppender(const LogString& name) const
{
	AppenderPtr result;
	std::lock_guard<std::recursive_mutex> lock( m_priv->m_mutex );
	auto it = std::find_if(m_priv->appenderList.begin(), m_priv->appenderList.end(),
		[&name](const AppenderPtr& appender) -> bool
		{ return name == appender->getName(); }
	);
	if (it != m_priv->appenderList.end())
		result = *it;
	return result;
}

bool AppenderAttachableImpl::isAttached(const AppenderPtr appender) const
{
	std::lock_guard<std::recursive_mutex> lock( m_priv->m_mutex );
	auto it = std::find(m_priv->appenderList.begin(), m_priv->appenderList.end(), appender);
	return it != m_priv->appenderList.end();
}

void AppenderAttachableImpl::removeAllAppenders()
{
	std::lock_guard<std::recursive_mutex> lock( m_priv->m_mutex );
	for (auto a : m_priv->appenderList)
		a->close();
	m_priv->appenderList.clear();
}

void AppenderAttachableImpl::removeAppender(const AppenderPtr appender)
{
	std::lock_guard<std::recursive_mutex> lock( m_priv->m_mutex );
	auto it = std::find(m_priv->appenderList.begin(), m_priv->appenderList.end(), appender);
	if (it != m_priv->appenderList.end())
		m_priv->appenderList.erase(it);
}

void AppenderAttachableImpl::removeAppender(const LogString& name)
{
	std::lock_guard<std::recursive_mutex> lock( m_priv->m_mutex );
	auto it = std::find_if(m_priv->appenderList.begin(), m_priv->appenderList.end(),
		[&name](const AppenderPtr& appender) -> bool
		{ return name == appender->getName(); }
	);
	if (it != m_priv->appenderList.end())
		m_priv->appenderList.erase(it);
}


