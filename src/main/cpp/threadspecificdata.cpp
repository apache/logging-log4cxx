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

#include <log4cxx/log4cxx.h>
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/threadspecificdata.h>
#include <log4cxx/helpers/exception.h>
#include <apr_thread_proc.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/helpers/aprinitializer.h>
#include <sstream>
#include <algorithm>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct ThreadSpecificData::ThreadSpecificDataPrivate{
	NDC::Stack ndcStack;
	MDC::Map mdcMap;
	LogString str[2];
#if !LOG4CXX_LOGCHAR_IS_UNICHAR && !LOG4CXX_LOGCHAR_IS_WCHAR
	std::basic_ostringstream<logchar> logchar_stringstream;
#endif
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
	std::basic_ostringstream<wchar_t> wchar_stringstream;
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
	std::basic_ostringstream<UniChar> unichar_stringstream;
#endif
};

ThreadSpecificData::ThreadSpecificData()
	: m_priv(std::make_unique<ThreadSpecificDataPrivate>())
{
}

ThreadSpecificData::ThreadSpecificData(ThreadSpecificData&& other)
	: m_priv(std::move(other.m_priv))
{
}

ThreadSpecificData::~ThreadSpecificData()
{
}


NDC::Stack& ThreadSpecificData::getStack()
{
	return m_priv->ndcStack;
}

MDC::Map& ThreadSpecificData::getMap()
{
	return m_priv->mdcMap;
}

LogString& ThreadSpecificData::getThreadIdString()
{
	return getCurrentData()->m_priv->str[0];
}

LogString& ThreadSpecificData::getThreadName()
{
	return getCurrentData()->m_priv->str[1];
}

#if !LOG4CXX_LOGCHAR_IS_UNICHAR && !LOG4CXX_LOGCHAR_IS_WCHAR
std::basic_ostringstream<logchar>& ThreadSpecificData::getStream(const logchar&)
{
	return getCurrentData()->m_priv->logchar_stringstream;
}
#endif

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
std::basic_ostringstream<wchar_t>& ThreadSpecificData::getStream(const wchar_t&)
{
	return getCurrentData()->m_priv->wchar_stringstream;
}
#endif

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
std::basic_ostringstream<UniChar>& ThreadSpecificData::getStream(const UniChar&)
{
	return getCurrentData()->m_priv->unichar_stringstream;
}
#endif

ThreadSpecificData* ThreadSpecificData::getCurrentData()
{
#if APR_HAS_THREADS
	void* pData = NULL;
	if (APR_SUCCESS == apr_threadkey_private_get(&pData, APRInitializer::getTlsKey())
		&& !pData)
	{
		pData = new ThreadSpecificData();
		if (APR_SUCCESS != apr_threadkey_private_set(pData, APRInitializer::getTlsKey()))
		{
			delete pData;
			pData = NULL;
		}
	}
	if (pData)
		return (ThreadSpecificData*) pData;
#elif LOG4CXX_HAS_THREAD_LOCAL
	thread_local ThreadSpecificData data;
	return &data;
#endif

	// Fallback implementation that is not expected to be used
#if LOG4CXX_HAS_PTHREAD_SELF && !(defined(_WIN32) && defined(_LIBCPP_VERSION))
	using ThreadIdType = pthread_t;
	ThreadIdType threadId = pthread_self();
#elif defined(_WIN32)
	using ThreadIdType = DWORD;
	ThreadIdType threadId = GetCurrentThreadId();
#else
	using ThreadIdType = int;
	ThreadIdType threadId = 0;
#endif
//#ifdef STD_PAIR_WITH_THREAD_SPECIFIC_DATA_COMPILES
#ifdef STD_PAIR_WITH_THREAD_SPECIFIC_DATA_COMPILES
	using TaggedData = std::pair<ThreadIdType, ThreadSpecificData>;
#else
	struct TaggedData
	{
		ThreadIdType first;
		ThreadSpecificData second;
		TaggedData(const ThreadIdType& id, ThreadSpecificData&& data)
			: first(id)
			, second(std::move(data))
		{}
	};
#endif
	static std::list<TaggedData> thread_id_map;
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock(mutex);
	auto pThreadId = std::find_if(thread_id_map.begin(), thread_id_map.end()
		, [threadId](const TaggedData& item) { return threadId == item.first; });
	if (thread_id_map.end() == pThreadId)
		pThreadId = thread_id_map.emplace(thread_id_map.begin(), threadId, ThreadSpecificData());
	return &pThreadId->second;
}

void ThreadSpecificData::recycle()
{
#if APR_HAS_THREADS
	if (m_priv->ndcStack.empty() && m_priv->mdcMap.empty())
	{
		void* pData = NULL;
		if (APR_SUCCESS == apr_threadkey_private_get(&pData, APRInitializer::getTlsKey())
			&& pData == this
			&& APR_SUCCESS == apr_threadkey_private_set(0, APRInitializer::getTlsKey()))
				delete this;
	}
#endif
}

void ThreadSpecificData::put(const LogString& key, const LogString& val)
{
	getCurrentData()->getMap()[key] = val;
}

void ThreadSpecificData::push(const LogString& val)
{
	NDC::Stack& stack = getCurrentData()->getStack();
	if (stack.empty())
	{
		stack.push(NDC::DiagnosticContext(val, val));
	}
	else
	{
		LogString fullMessage(stack.top().second);
		fullMessage.append(1, (logchar) 0x20);
		fullMessage.append(val);
		stack.push(NDC::DiagnosticContext(val, fullMessage));
	}
}

void ThreadSpecificData::inherit(const NDC::Stack& src)
{
	getCurrentData()->getStack() = src;
}

