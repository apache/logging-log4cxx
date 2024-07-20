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
	if (auto data = getCurrentData())
		return data->m_priv->str[0];
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
	using ListItem = std::pair<ThreadIdType, LogString>;
	static std::list<ListItem> thread_id_map;
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock(mutex);
	auto pThreadId = std::find_if(thread_id_map.begin(), thread_id_map.end()
		, [threadId](const ListItem& item) { return threadId == item.first; });
	if (thread_id_map.end() == pThreadId)
		pThreadId = thread_id_map.insert(thread_id_map.begin(), ListItem(threadId, LogString()));
	return pThreadId->second;
}

LogString& ThreadSpecificData::getThreadName()
{
	if (auto data = getCurrentData())
		return data->m_priv->str[1];
	static LogString thread_name = LOG4CXX_STR("(noname)");
	return thread_name;
}

#if !LOG4CXX_LOGCHAR_IS_UNICHAR && !LOG4CXX_LOGCHAR_IS_WCHAR
std::basic_ostringstream<logchar>& ThreadSpecificData::getStream(const logchar&)
{
	if (auto data = getCurrentData())
		return data->m_priv->logchar_stringstream;
	static std::basic_ostringstream<logchar> ss;
	return ss;
}
#endif

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
std::basic_ostringstream<wchar_t>& ThreadSpecificData::getStream(const wchar_t&)
{
	if (auto data = getCurrentData())
		return data->m_priv->wchar_stringstream;
	static std::basic_ostringstream<wchar_t> ss;
	return ss;
}
#endif

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
std::basic_ostringstream<UniChar>& ThreadSpecificData::getStream(const UniChar&)
{
	if (auto data = getCurrentData())
		return data->m_priv->unichar_stringstream;
	static std::basic_ostringstream<UniChar> ss;
	return ss;
}
#endif

ThreadSpecificData& ThreadSpecificData::getDataNoThreads()
{
	static WideLife<ThreadSpecificData> noThreadData;
	return noThreadData;
}

ThreadSpecificData* ThreadSpecificData::getCurrentData()
{
#if APR_HAS_THREADS
	void* pData = NULL;
	apr_threadkey_private_get(&pData, APRInitializer::getTlsKey());
	if (!pData)
	{
		pData = new ThreadSpecificData();
		apr_threadkey_private_set(pData, APRInitializer::getTlsKey());
	}
	return (ThreadSpecificData*) pData;
#elif LOG4CXX_HAS_THREAD_LOCAL
	thread_local ThreadSpecificData data;
	return &data;
#else
	return &getDataNoThreads();
#endif
}

void ThreadSpecificData::recycle()
{
#if APR_HAS_THREADS

	if (m_priv->ndcStack.empty() && m_priv->mdcMap.empty())
	{
		void* pData = NULL;
		apr_status_t stat = apr_threadkey_private_get(&pData, APRInitializer::getTlsKey());

		if (stat == APR_SUCCESS && pData == this)
		{
			stat = apr_threadkey_private_set(0, APRInitializer::getTlsKey());

			if (stat == APR_SUCCESS)
			{
				delete this;
			}
		}
	}

#endif
}

void ThreadSpecificData::put(const LogString& key, const LogString& val)
{
	if (auto data = getCurrentData())
	{
		data->getMap()[key] = val;
	}
}




void ThreadSpecificData::push(const LogString& val)
{
	if (auto data = getCurrentData())
	{
		NDC::Stack& stack = data->getStack();

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
}

void ThreadSpecificData::inherit(const NDC::Stack& src)
{
	if (auto data = getCurrentData())
	{
		data->getStack() = src;
	}
}

