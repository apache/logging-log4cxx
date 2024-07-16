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
#include <log4cxx/helpers/appenderattachableimpl.h>
#include <algorithm>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(AppenderAttachableImpl)

struct AppenderAttachableImpl::priv_data
{
	/** Array of appenders. */
	AppenderList  appenderList;
	mutable std::mutex m_mutex;
};

AppenderAttachableImpl::AppenderAttachableImpl()
{
}

#if LOG4CXX_ABI_VERSION <= 15
AppenderAttachableImpl::AppenderAttachableImpl(Pool& pool)
	: m_priv()
{
}
#endif

AppenderAttachableImpl::~AppenderAttachableImpl()
{

}

void AppenderAttachableImpl::addAppender(const AppenderPtr newAppender)
{
	// Null values for newAppender parameter are strictly forbidden.
	if (!newAppender)
	{
		return;
	}
	if (!m_priv)
		m_priv = std::make_unique<AppenderAttachableImpl::priv_data>();

	std::lock_guard<std::mutex> lock( m_priv->m_mutex );
	AppenderList::iterator it = std::find(
			m_priv->appenderList.begin(), m_priv->appenderList.end(), newAppender);

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
	if (m_priv)
	{
		// FallbackErrorHandler::error() may modify our list of appenders
		// while we are iterating over them (if it holds the same logger).
		// So, make a local copy of the appenders that we want to iterate over
		// before actually iterating over them.
		AppenderList allAppenders = getAllAppenders();
		for (auto appender : allAppenders)
		{
			appender->doAppend(event, p);
			numberAppended++;
		}
	}

	return numberAppended;
}

AppenderList AppenderAttachableImpl::getAllAppenders() const
{
	AppenderList result;
	if (m_priv)
	{
		std::lock_guard<std::mutex> lock( m_priv->m_mutex );
		result = m_priv->appenderList;
	}
	return result;
}

AppenderPtr AppenderAttachableImpl::getAppender(const LogString& name) const
{
	AppenderPtr result;
	if (m_priv && !name.empty())
	{
		std::lock_guard<std::mutex> lock( m_priv->m_mutex );
		for (auto appender : m_priv->appenderList)
		{
			if (name == appender->getName())
			{
				result = appender;
				break;
			}
		}
	}
	return result;
}

bool AppenderAttachableImpl::isAttached(const AppenderPtr appender) const
{
	bool result = false;
	if (m_priv && appender)
	{
		std::lock_guard<std::mutex> lock( m_priv->m_mutex );
		result = std::find(m_priv->appenderList.begin(), m_priv->appenderList.end(), appender) != m_priv->appenderList.end();
	}
	return result;
}

void AppenderAttachableImpl::removeAllAppenders()
{
	if (m_priv)
	{
		for (auto a : getAllAppenders())
			a->close();
		std::lock_guard<std::mutex> lock( m_priv->m_mutex );
		m_priv->appenderList.clear();
	}
}

void AppenderAttachableImpl::removeAppender(const AppenderPtr appender)
{
	if (m_priv && appender)
	{
		std::lock_guard<std::mutex> lock( m_priv->m_mutex );
		auto it = std::find(m_priv->appenderList.begin(), m_priv->appenderList.end(), appender);
		if (it != m_priv->appenderList.end())
		{
			m_priv->appenderList.erase(it);
		}
	}
}

void AppenderAttachableImpl::removeAppender(const LogString& name)
{
	if (m_priv && !name.empty())
	{
		std::lock_guard<std::mutex> lock( m_priv->m_mutex );
		auto it = std::find_if(m_priv->appenderList.begin(), m_priv->appenderList.end()
			, [&name](const AppenderPtr& appender) -> bool
			{
				return name == appender->getName();
			});
		if (it != m_priv->appenderList.end())
			m_priv->appenderList.erase(it);
	}
}


