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
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/helpers/aprinitializer.h>
#include <apr_pools.h>
#include <assert.h>
#include <log4cxx/helpers/threadspecificdata.h>
#include <apr_thread_proc.h>
#include <log4cxx/helpers/filewatchdog.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/helpers/loglog.h>
#include <list>
#include <algorithm>

using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS;

bool APRInitializer::isDestructed = false;

using IdentifiedObject = std::pair<size_t, ObjectPtr>;

struct APRInitializer::APRInitializerPrivate{
	APRInitializerPrivate() :
		p(0),
		startTime(0),
		tlsKey(0){

	}
	~APRInitializerPrivate()
	{
		// Delete in reverse order
		while (!objects.empty())
			objects.pop_back();
	}

	apr_pool_t* p;
	std::mutex mutex;
	std::list<FileWatchdog*> watchdogs;
	log4cxx_time_t startTime;
	apr_threadkey_t* tlsKey;
	std::vector<IdentifiedObject> objects;
};

namespace
{
void tlsDestructImpl(void* ptr)
{
	delete ((ThreadSpecificData*) ptr);
}
}

#if LOG4CXX_ABI_VERSION <= 15
extern "C" void tlsDestruct(void* ptr)
{
	return tlsDestructImpl(ptr);
}
#endif

namespace
{
// The first object created and the last object destroyed
struct apr_environment
{
    apr_environment()
    {
        apr_initialize();
    }
    ~apr_environment()
    {
        apr_terminate();
    }
};

}


APRInitializer::APRInitializer() :
	m_priv(std::make_unique<APRInitializerPrivate>())
{
	apr_pool_create(&m_priv->p, NULL);
	m_priv->startTime = Date::currentTime();
#if APR_HAS_THREADS
	apr_status_t stat = apr_threadkey_private_create(&m_priv->tlsKey, tlsDestructImpl, m_priv->p);
	assert(stat == APR_SUCCESS);
#endif
}

APRInitializer::~APRInitializer()
{
	stopWatchDogs();
	isDestructed = true;
#if APR_HAS_THREADS
	std::lock_guard<std::mutex> lock(m_priv->mutex);
	apr_threadkey_private_delete(m_priv->tlsKey);
#endif
}

void APRInitializer::stopWatchDogs()
{
	std::lock_guard<std::mutex> lock(m_priv->mutex);

	while (!m_priv->watchdogs.empty())
	{
		m_priv->watchdogs.back()->stop();
		delete m_priv->watchdogs.back();
		m_priv->watchdogs.pop_back();
	}
}

void APRInitializer::unregisterAll()
{
	getInstance().stopWatchDogs();
}

APRInitializer& APRInitializer::getInstance()
{
	static WideLife<apr_environment> env;
	static WideLife<APRInitializer> init;
	return init;
}


#if LOG4CXX_ABI_VERSION <= 15
log4cxx_time_t APRInitializer::initialize()
{
	return getInstance().m_priv->startTime;
}
#endif

log4cxx_time_t APRInitializer::getStartTime()
{
	return getInstance().m_priv->startTime;
}

apr_pool_t* APRInitializer::getRootPool()
{
	return getInstance().m_priv->p;
}

apr_threadkey_t* APRInitializer::getTlsKey()
{
	return getInstance().m_priv->tlsKey;
}

void APRInitializer::registerCleanup(FileWatchdog* watchdog)
{
	APRInitializer& instance(getInstance());
	std::lock_guard<std::mutex> lock(instance.m_priv->mutex);
	instance.m_priv->watchdogs.push_back(watchdog);
}

void APRInitializer::unregisterCleanup(FileWatchdog* watchdog)
{
	APRInitializer& instance(getInstance());
	std::lock_guard<std::mutex> lock(instance.m_priv->mutex);

	auto iter = std::find(instance.m_priv->watchdogs.begin(), instance.m_priv->watchdogs.end(), watchdog);
	if (iter != instance.m_priv->watchdogs.end())
		instance.m_priv->watchdogs.erase(iter);
}

void APRInitializer::addObject(size_t key, const ObjectPtr& pObject)
{
	std::lock_guard<std::mutex> lock(m_priv->mutex);
	auto pItem = std::find_if(m_priv->objects.begin(), m_priv->objects.end()
		, [key](const IdentifiedObject& item) { return item.first == key; }
		);
	if (m_priv->objects.end() != pItem)
		pItem->second = pObject;
	else
		m_priv->objects.emplace_back(key, pObject);
}

const ObjectPtr& APRInitializer::findOrAddObject(size_t key, std::function<ObjectPtr()> creator)
{
	std::lock_guard<std::mutex> lock(m_priv->mutex);
	if (m_priv->objects.empty())
	{
		// Ensure the internal logger has a longer life than other Log4cxx static data
		LogLog::debug(LOG4CXX_STR("Started"));
	}
	auto pItem = std::find_if(m_priv->objects.begin(), m_priv->objects.end()
		, [key](const IdentifiedObject& item) { return item.first == key; }
		);
	if (m_priv->objects.end() != pItem)
		return pItem->second;
	m_priv->objects.emplace_back(key, creator());
	return m_priv->objects.back().second;
}
