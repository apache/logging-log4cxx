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

using AppenderListPtr = std::shared_ptr<const AppenderList>;

/** A vector of appender pointers. */
struct AppenderAttachableImpl::priv_data
{
private: // Attributes
#ifdef __cpp_lib_atomic_shared_ptr
	std::atomic<AppenderListPtr> pAppenderList;
#else // !defined(__cpp_lib_atomic_shared_ptr)
	AppenderListPtr    pAppenderList;
	mutable std::mutex m_mutex;
#endif // !defined(__cpp_lib_atomic_shared_ptr)

public: // ...structors
	priv_data(const AppenderList& newList = {})
		: pAppenderList{ std::make_shared<const AppenderList>(newList) }
	{}

public: // Accessors
	AppenderListPtr getAppenders() const
	{
#ifdef __cpp_lib_atomic_shared_ptr
		return pAppenderList.load(std::memory_order_acquire);
#else // !defined(__cpp_lib_atomic_shared_ptr)
		std::lock_guard<std::mutex> lock( m_mutex );
		return pAppenderList;
#endif // !defined(__cpp_lib_atomic_shared_ptr)
	}

public: // Modifiers
	void setAppenders(const AppenderList& newList)
	{
#ifdef __cpp_lib_atomic_shared_ptr
		pAppenderList.store(std::make_shared<AppenderList>(newList), std::memory_order_release);
#else // !defined(__cpp_lib_atomic_shared_ptr)
		std::lock_guard<std::mutex> lock( m_mutex );
		pAppenderList = std::make_shared<const AppenderList>(newList);
#endif // !defined(__cpp_lib_atomic_shared_ptr)
	}
};

AppenderAttachableImpl::AppenderAttachableImpl()
{
}

#if LOG4CXX_ABI_VERSION <= 15
AppenderAttachableImpl::AppenderAttachableImpl(Pool& pool)
{
}
#endif
AppenderAttachableImpl::~AppenderAttachableImpl()
{
}


void AppenderAttachableImpl::addAppender(const AppenderPtr newAppender)
{
	if (!newAppender)
		return;
	if (m_priv)
	{
		auto allAppenders = m_priv->getAppenders();
		if (allAppenders->end() == std::find(allAppenders->begin(), allAppenders->end(), newAppender))
		{
			auto newAppenders = *allAppenders;
			newAppenders.push_back(newAppender);
			m_priv->setAppenders(newAppenders);
		}
	}
	else
		m_priv = std::make_unique<priv_data>(AppenderList{newAppender});
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
		m_priv->setAppenders({});
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
			m_priv->setAppenders(newAppenders);
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
			m_priv->setAppenders(newAppenders);
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
			m_priv->setAppenders(newAppenders);
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
		m_priv->setAppenders(newList);
	}
	else
		m_priv = std::make_unique<priv_data>(newList);
}


