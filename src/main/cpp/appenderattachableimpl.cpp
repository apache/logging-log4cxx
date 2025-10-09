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

#ifndef __cpp_lib_atomic_shared_ptr

struct AppenderAttachableImpl::priv_data
{
	/** Array of appenders. */
	AppenderList  appenderList;
	mutable std::mutex m_mutex;
};

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

bool AppenderAttachableImpl::replaceAppender(const AppenderPtr& oldAppender, const AppenderPtr& newAppender)
{
	bool found = false;
	if (m_priv && oldAppender && newAppender)
	{
		auto oldName = oldAppender->getName();
		std::lock_guard<std::mutex> lock( m_priv->m_mutex );
		auto it = std::find_if(m_priv->appenderList.begin(), m_priv->appenderList.end()
			, [&oldName](const AppenderPtr& appender) -> bool
			{
				return oldName == appender->getName();
			});
		if (it != m_priv->appenderList.end())
		{
			*it = newAppender;
			found = true;
		}
	}
	return found;
}

void AppenderAttachableImpl::replaceAppenders(const AppenderList& newList)
{
	auto oldAppenders = getAllAppenders();
	if (!m_priv)
		m_priv = std::make_unique<AppenderAttachableImpl::priv_data>();
	std::lock_guard<std::mutex> lock( m_priv->m_mutex );
	for (auto a : oldAppenders)
		a->close();
	m_priv->appenderList = newList;
}

#else // __cpp_lib_atomic_shared_ptr

using AppenderListPtr = std::shared_ptr<const AppenderList>;

/** A vector of appender pointers. */
struct AppenderAttachableImpl::priv_data
{
	std::atomic<AppenderListPtr> pAppenderList;

	priv_data(const AppenderList& newList = {})
		: pAppenderList{ std::make_shared<AppenderList>(newList) }
	{}

	AppenderListPtr getAppenders() const
	{
		return pAppenderList.load(std::memory_order_acquire);
	}

	void setAppenders(const AppenderListPtr& newList)
	{
		pAppenderList.store(newList, std::memory_order_release);
	}
};

void AppenderAttachableImpl::addAppender(const AppenderPtr newAppender)
{
	if (!newAppender)
		return;
	if (m_priv)
	{
		auto allAppenders = m_priv->getAppenders();
		if (allAppenders->end() == std::find(allAppenders->begin(), allAppenders->end(), newAppender))
		{
			auto newAppenders = std::make_shared<AppenderList>(*allAppenders);
			newAppenders->push_back(newAppender);
			m_priv->setAppenders(newAppenders);
		}
	}
	else
		m_priv = std::make_unique<AppenderAttachableImpl::priv_data>(AppenderList{newAppender});
}

int AppenderAttachableImpl::appendLoopOnAppenders(const spi::LoggingEventPtr& event, Pool& p)
{
	int result = 0;
	if (m_priv)
	{
		auto allAppenders = m_priv->getAppenders();
		for (auto& appender : *allAppenders)
		{
			appender->doAppend(event, p);
			++result;
		}
	}
	return result;
}

AppenderList AppenderAttachableImpl::getAllAppenders() const
{
	AppenderList result;
	if (m_priv)
		result = *m_priv->getAppenders();
	return result;
}

AppenderPtr AppenderAttachableImpl::getAppender(const LogString& name) const
{
	AppenderPtr result;
	if (m_priv)
	{
		auto allAppenders = m_priv->getAppenders();
		for (auto& appender : *allAppenders)
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
		auto allAppenders = m_priv->getAppenders();
		result = allAppenders->end() != std::find(allAppenders->begin(), allAppenders->end(), appender);
	}
	return result;
}

void AppenderAttachableImpl::removeAllAppenders()
{
	if (m_priv)
	{
		auto allAppenders = m_priv->getAppenders();
		for (auto& appender : *allAppenders)
			appender->close();
		m_priv->setAppenders(std::make_shared<AppenderList>());
	}
}

void AppenderAttachableImpl::removeAppender(const AppenderPtr appender)
{
	if (m_priv && appender)
	{
		auto newAppenders = *m_priv->getAppenders();
		auto pItem = std::find(newAppenders.begin(), newAppenders.end(), appender);
		if (newAppenders.end() != pItem)
		{
			newAppenders.erase(pItem);
			m_priv->setAppenders(std::make_shared<AppenderList>(newAppenders));
		}
	}
}

void AppenderAttachableImpl::removeAppender(const LogString& name)
{
	if (m_priv)
	{
		auto newAppenders = *m_priv->getAppenders();
		auto pItem = std::find_if(newAppenders.begin(), newAppenders.end()
			, [&name](const AppenderPtr& appender) -> bool
			{
				return name == appender->getName();
			});
		if (newAppenders.end() != pItem)
		{
			newAppenders.erase(pItem);
			m_priv->setAppenders(std::make_shared<AppenderList>(newAppenders));
		}
	}
}

bool AppenderAttachableImpl::replaceAppender(const AppenderPtr& oldAppender, const AppenderPtr& newAppender)
{
	bool found = false;
	if (m_priv && oldAppender && newAppender)
	{
		auto name = oldAppender->getName();
		auto newAppenders = *m_priv->getAppenders();
		auto pItem = std::find_if(newAppenders.begin(), newAppenders.end()
			, [&name](const AppenderPtr& appender) -> bool
			{
				return name == appender->getName();
			});
		if (newAppenders.end() != pItem)
		{
			*pItem = newAppender;
			m_priv->setAppenders(std::make_shared<AppenderList>(newAppenders));
			found = true;
		}
	}
	return found;
}

void AppenderAttachableImpl::replaceAppenders(const AppenderList& newList)
{
	if (m_priv)
	{
		auto allAppenders = m_priv->getAppenders();
		for (auto& a : *allAppenders)
			a->close();
		m_priv->setAppenders(std::make_shared<AppenderList>(newList));
	}
	else
		m_priv = std::make_unique<AppenderAttachableImpl::priv_data>(newList);
}

#endif // __cpp_lib_atomic_shared_ptr

AppenderAttachableImpl::AppenderAttachableImpl()
{
}

AppenderAttachableImpl::~AppenderAttachableImpl()
{
}

#if LOG4CXX_ABI_VERSION <= 15
AppenderAttachableImpl::AppenderAttachableImpl(Pool& pool)
{
}
#endif


