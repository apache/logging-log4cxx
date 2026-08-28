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

public: // Attributes
	/**
	Serializes read-copy-update writers (addAppender, removeAppender, etc.)
	so a concurrent modification is not silently lost. Readers stay lock-free.
	*/
	mutable std::mutex m_writeMutex;

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
	: m_priv(std::make_unique<priv_data>())
{
}

#if LOG4CXX_ABI_VERSION <= 15
AppenderAttachableImpl::AppenderAttachableImpl(Pool& pool)
	: m_priv(std::make_unique<priv_data>())
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
	std::lock_guard<std::mutex> lock(m_priv->m_writeMutex);
	auto allAppenders = m_priv->getAppenders();
	if (allAppenders->end() == std::find(allAppenders->begin(), allAppenders->end(), newAppender))
	{
		auto newAppenders = *allAppenders;
		newAppenders.push_back(newAppender);
		m_priv->setAppenders(newAppenders);
	}
}

int AppenderAttachableImpl::appendLoopOnAppenders(const spi::LoggingEventPtr& event)
{
	int result = 0;
	auto allAppenders = m_priv->getAppenders();
	for (auto& appender : *allAppenders)
	{
		appender->doAppend(event);
		++result;
	}
	return result;
}
#if LOG4CXX_ABI_VERSION <= 15
int AppenderAttachableImpl::appendLoopOnAppenders(const spi::LoggingEventPtr& event, helpers::Pool& p)
{
	return appendLoopOnAppenders(event);
}
#endif

AppenderList AppenderAttachableImpl::getAllAppenders() const
{
	return *m_priv->getAppenders();
}

AppenderPtr AppenderAttachableImpl::getAppender(const LogString& name) const
{
	AppenderPtr result;
	auto allAppenders = m_priv->getAppenders();
	for (auto& appender : *allAppenders)
	{
		if (name == appender->getName())
		{
			result = appender;
			break;
		}
	}
	return result;
}

bool AppenderAttachableImpl::isAttached(const AppenderPtr appender) const
{
	bool result = false;
	if (appender)
	{
		auto allAppenders = m_priv->getAppenders();
		result = allAppenders->end() != std::find(allAppenders->begin(), allAppenders->end(), appender);
	}
	return result;
}

void AppenderAttachableImpl::removeAllAppenders()
{
	std::lock_guard<std::mutex> lock(m_priv->m_writeMutex);
	auto allAppenders = m_priv->getAppenders();
	for (auto& appender : *allAppenders)
		appender->close();
	m_priv->setAppenders({});
}

void AppenderAttachableImpl::removeAppender(const AppenderPtr appender)
{
	if (appender)
	{
		std::lock_guard<std::mutex> lock(m_priv->m_writeMutex);
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
	std::lock_guard<std::mutex> lock(m_priv->m_writeMutex);
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

bool AppenderAttachableImpl::replaceAppender(const AppenderPtr& oldAppender, const AppenderPtr& newAppender)
{
	bool found = false;
	if (oldAppender && newAppender)
	{
		std::lock_guard<std::mutex> lock(m_priv->m_writeMutex);
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
	std::lock_guard<std::mutex> lock(m_priv->m_writeMutex);
	auto allAppenders = m_priv->getAppenders();
	for (auto& a : *allAppenders)
		a->close();
	m_priv->setAppenders(newList);
}


