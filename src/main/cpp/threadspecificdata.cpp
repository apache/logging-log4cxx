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
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <apr_thread_proc.h>
#include <apr_strings.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>
#include <log4cxx/helpers/aprinitializer.h>
#include <sstream>
#include <algorithm>
#include <thread>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct ThreadSpecificData::ThreadSpecificDataPrivate{
	ThreadSpecificDataPrivate()
		: pNamePair(std::make_shared<NamePair>())
	{
		setThreadIdName();
		setThreadUserName();
	}
	NDC::Stack ndcStack;
	MDC::Map mdcMap;

	std::shared_ptr<NamePair> pNamePair;

#if !LOG4CXX_LOGCHAR_IS_UNICHAR && !LOG4CXX_LOGCHAR_IS_WCHAR
	std::basic_ostringstream<logchar> logchar_stringstream;
#endif
#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR
	std::basic_ostringstream<wchar_t> wchar_stringstream;
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
	std::basic_ostringstream<UniChar> unichar_stringstream;
#endif

	void setThreadIdName();
	void setThreadUserName();
};

/* Generate an identifier for the current thread
*/
void ThreadSpecificData::ThreadSpecificDataPrivate::setThreadIdName()
{
#if LOG4CXX_HAS_PTHREAD_SELF && !(defined(_WIN32) && defined(_LIBCPP_VERSION))
	// pthread_t encoded in HEX takes needs as many characters
	// as two times the size of the type, plus an additional null byte.
	auto threadId = pthread_self();
	char result[sizeof(pthread_t) * 3 + 10];
	apr_snprintf(result, sizeof(result), LOG4CXX_APR_THREAD_FMTSPEC, (void*) &threadId);
	this->pNamePair->idString = Transcoder::decode(result);
#elif defined(_WIN32)
	char result[20];
	apr_snprintf(result, sizeof(result), LOG4CXX_WIN32_THREAD_FMTSPEC, GetCurrentThreadId());
	this->pNamePair->idString = Transcoder::decode(result);
#else
	std::stringstream ss;
	ss << std::hex << "0x" << std::this_thread::get_id();
	this->pNamePair->idString = Transcoder::decode(ss.str().c_str());
#endif
}

/*
 * Get the user-specified name of the current thread (on a per-platform basis).
 * This is set using a method such as pthread_setname_np on POSIX
 * systems or SetThreadDescription on Windows.
 */
void ThreadSpecificData::ThreadSpecificDataPrivate::setThreadUserName()
{
#if LOG4CXX_HAS_PTHREAD_GETNAME && !(defined(_WIN32) && defined(_LIBCPP_VERSION))
	char result[16];
	pthread_t current_thread = pthread_self();
	if (pthread_getname_np(current_thread, result, sizeof(result)) < 0 || 0 == result[0])
		this->pNamePair->threadName = this->pNamePair->idString;
	else
		this->pNamePair->threadName = Transcoder::decode(result);
#elif defined(_WIN32)
	typedef HRESULT (WINAPI *TGetThreadDescription)(HANDLE, PWSTR*);
	static struct initialiser
	{
		HMODULE hKernelBase;
		TGetThreadDescription GetThreadDescription;
		initialiser()
			: hKernelBase(GetModuleHandleA("KernelBase.dll"))
			, GetThreadDescription(nullptr)
		{
			if (hKernelBase)
				GetThreadDescription = reinterpret_cast<TGetThreadDescription>(GetProcAddress(hKernelBase, "GetThreadDescription"));
		}
	} win32func;
	if (win32func.GetThreadDescription)
	{
		PWSTR result = 0;
		HRESULT hr = win32func.GetThreadDescription(GetCurrentThread(), &result);
		if (SUCCEEDED(hr) && result)
		{
			std::wstring wresult = result;
			LOG4CXX_DECODE_WCHAR(decoded, wresult);
			LocalFree(result);
			this->pNamePair->threadName = decoded;
		}
	}
	if (this->pNamePair->threadName.empty())
		this->pNamePair->threadName = this->pNamePair->idString;
#else
	this->pNamePair->threadName = this->pNamePair->idString;
#endif
}

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
	m_priv.reset();
}

NDC::Stack& ThreadSpecificData::getStack()
{
	return m_priv->ndcStack;
}

MDC::Map& ThreadSpecificData::getMap()
{
	return m_priv->mdcMap;
}

auto ThreadSpecificData::getNames() -> NamePairPtr
{
	auto p = getCurrentData();
	return p ? p->m_priv->pNamePair : std::make_shared<NamePair>();
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
#if LOG4CXX_HAS_THREAD_LOCAL
	thread_local ThreadSpecificData data;
	return data.m_priv ? &data : NULL;
#elif APR_HAS_THREADS
	void* pData = NULL;
	if (APR_SUCCESS == apr_threadkey_private_get(&pData, APRInitializer::getTlsKey())
		&& !pData)
	{
		pData = new ThreadSpecificData();
		if (APR_SUCCESS != apr_threadkey_private_set(pData, APRInitializer::getTlsKey()))
		{
			delete (ThreadSpecificData*)pData;
			pData = NULL;
		}
	}
	if (pData)
		return (ThreadSpecificData*) pData;
#endif

	// Fallback implementation that is not expected to be used
	using TaggedData = std::pair<std::thread::id, ThreadSpecificData>;
	static std::list<TaggedData> thread_id_map;
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock(mutex);
	auto threadId = std::this_thread::get_id();
	auto pThreadId = std::find_if(thread_id_map.begin(), thread_id_map.end()
		, [threadId](const TaggedData& item) { return threadId == item.first; });
	if (thread_id_map.end() == pThreadId)
		pThreadId = thread_id_map.emplace(thread_id_map.begin(), threadId, ThreadSpecificData());
	return &pThreadId->second;
}

void ThreadSpecificData::recycle()
{
#if !LOG4CXX_HAS_THREAD_LOCAL && APR_HAS_THREADS
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
	if (auto p = getCurrentData())
		p->getMap()[key] = val;
}

void ThreadSpecificData::push(const LogString& val)
{
	auto p = getCurrentData();
	if (!p)
		return;
	NDC::Stack& stack = p->getStack();
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
	if (auto p = getCurrentData())
		p->getStack() = src;
}

