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

#include <chrono>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/ndc.h>

#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/helpers/socket.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/helpers/aprinitializer.h>
#include <log4cxx/helpers/threadspecificdata.h>
#include <log4cxx/helpers/transcoder.h>

#include <apr_portable.h>
#include <apr_strings.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/logger.h>
#include <log4cxx/private/log4cxx_private.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/helpers/optional.h>
#include <thread>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

struct LoggingEvent::LoggingEventPrivate
{
	LoggingEventPrivate() :
		timeStamp(0),
		threadName(getCurrentThreadName()),
		threadUserName(getCurrentThreadUserName())
	{
	}

	LoggingEventPrivate
		( const LogString& logger1
		, const LevelPtr& level1
		, const LocationInfo& locationInfo1
		, LogString&& message1
		) :
		logger(logger1),
		level(level1),
		message(std::move(message1)),
		timeStamp(Date::currentTime()),
		locationInfo(locationInfo1),
		threadName(getCurrentThreadName()),
		threadUserName(getCurrentThreadUserName()),
		chronoTimeStamp(std::chrono::microseconds(timeStamp))
	{
	}

	LoggingEventPrivate(
		const LogString& logger1, const LevelPtr& level1,
		const LogString& message1, const LocationInfo& locationInfo1) :
		logger(logger1),
		level(level1),
		message(message1),
		timeStamp(Date::currentTime()),
		locationInfo(locationInfo1),
		threadName(getCurrentThreadName()),
		threadUserName(getCurrentThreadUserName()),
		chronoTimeStamp(std::chrono::microseconds(timeStamp))
	{
	}

	~LoggingEventPrivate()
	{
		delete properties;
	}

	/**
	* The logger of the logging event.
	**/
	LogString logger;

	/** level of logging event. */
	LevelPtr level;

#if LOG4CXX_ABI_VERSION <= 15
	/** The nested diagnostic context (NDC) of logging event. */
	mutable LogString* ndc{NULL};

	/** The mapped diagnostic context (MDC) of logging event. */
	mutable MDC::Map* mdcCopy{NULL};
#endif

	/**
	* A map of String keys and String values.
	*/
	std::map<LogString, LogString>* properties{NULL};

#if LOG4CXX_ABI_VERSION <= 15
	/** Have we tried to do an NDC lookup? If we did, there is no need
	*  to do it again.  Note that its value is always false when
	*  serialized. Thus, a receiving SocketNode will never use it's own
	*  (incorrect) NDC. See also writeObject method.
	*/
	mutable bool ndcLookupRequired{false};

	/**
	* Have we tried to do an MDC lookup? If we did, there is no need to do it
	* again.  Note that its value is always false when serialized. See also
	* the getMDC and getMDCCopy methods.
	*/
	mutable bool mdcCopyLookupRequired{false};
#endif

	/** The application supplied message of logging event. */
	LogString message;


	/** The number of microseconds elapsed from 01.01.1970 until logging event
	 was created. */
	log4cxx_time_t timeStamp;

	/** The is the location where this log statement was written. */
	const LOG4CXX_NS::spi::LocationInfo locationInfo;


	/** The identifier of thread in which this logging event
	was generated.
	*/
	const LogString& threadName;

	/**
	 * The user-specified name of the thread(on a per-platform basis).
	 * This is set using a method such as pthread_setname_np on POSIX
	 * systems or SetThreadDescription on Windows.
	 */
	const LogString& threadUserName;

	std::chrono::time_point<std::chrono::system_clock> chronoTimeStamp;

	ThreadSpecificData::OtherDataPtr pNames = ThreadSpecificData::getCurrentData()->getOtherData();

	struct DiagnosticContext
	{
		Optional<NDC::DiagnosticContext> ctx;
		MDC::Map map;
	};
	mutable std::unique_ptr<DiagnosticContext> dc;
};

IMPLEMENT_LOG4CXX_OBJECT(LoggingEvent)


//
//   Accessor for start time.
//
log4cxx_time_t LoggingEvent::getStartTime()
{
	return APRInitializer::getStartTime();
}

LoggingEvent::LoggingEvent() :
	m_priv(std::make_unique<LoggingEventPrivate>())
{
}

LoggingEvent::LoggingEvent
	( const LogString&    logger
	, const LevelPtr&     level
	, const LocationInfo& location
	, LogString&&         message
	)
	: m_priv(std::make_unique<LoggingEventPrivate>(logger, level, location, std::move(message)))
{
}

LoggingEvent::LoggingEvent(
	const LogString& logger1, const LevelPtr& level1,
	const LogString& message1, const LocationInfo& locationInfo1) :
	m_priv(std::make_unique<LoggingEventPrivate>(logger1, level1, message1, locationInfo1))
{
}

LoggingEvent::~LoggingEvent()
{
}

const LogString& LoggingEvent::getThreadUserName() const
{
	return m_priv->threadUserName;
}

bool LoggingEvent::getNDC(LogString& dest) const
{
	bool result = false;
	// Use the copy of the diagnostic context if it exists.
	// Otherwise use the NDC that is associated with the thread.
	if (m_priv->dc)
	{
		if (result = m_priv->dc->ctx.has_value())
			dest.append(NDC::getFullMessage(m_priv->dc->ctx.value()));
	}
	else
		result = NDC::get(dest);
	return result;
}

bool LoggingEvent::getMDC(const LogString& key, LogString& dest) const
{
	bool result = false;
	// Use the copy of the diagnostic context if it exists.
	// Otherwise use the MDC that is associated with the thread.
	if (m_priv->dc)
	{
		auto& map = m_priv->dc->map;
		auto it = map.find(key);
		if (it != map.end() && !it->second.empty())
		{
			dest.append(it->second);
			result = true;
		}
	}
	else
		result = MDC::get(key, dest);
	return result;
}

LoggingEvent::KeySet LoggingEvent::getMDCKeySet() const
{
	LoggingEvent::KeySet result;
	if (m_priv->dc)
	{
		for (auto const& item : m_priv->dc->map)
			result.push_back(item.first);
	}
	else for (auto const& item : ThreadSpecificData::getCurrentData()->getMap())
		result.push_back(item.first);
	return result;
}

void LoggingEvent::LoadDC() const
{
	m_priv->dc = std::make_unique<LoggingEventPrivate::DiagnosticContext>();
	auto pData = ThreadSpecificData::getCurrentData();
	m_priv->dc->map = pData->getMap();
	auto& stack = pData->getStack();
	if (!stack.empty())
		m_priv->dc->ctx = stack.top();
}

#if LOG4CXX_ABI_VERSION <= 15
void LoggingEvent::getMDCCopy() const
{
	if (!m_priv->dc)
		LoadDC();
}
#endif

bool LoggingEvent::getProperty(const LogString& key, LogString& dest) const
{
	if (m_priv->properties == 0)
	{
		return false;
	}

	std::map<LogString, LogString>::const_iterator  it = m_priv->properties->find(key);

	if (it != m_priv->properties->end())
	{
		dest.append(it->second);
		return true;
	}

	return false;
}

LoggingEvent::KeySet LoggingEvent::getPropertyKeySet() const
{
	LoggingEvent::KeySet set;

	if (m_priv->properties)
	{
		for (auto item : *m_priv->properties)
		{
			set.push_back(item.first);
		}
	}

	return set;
}


const LogString& LoggingEvent::getCurrentThreadName()
{
	LogString& thread_id_string = ThreadSpecificData::getThreadIdString();
	if ( !thread_id_string.empty() )
	{
		return thread_id_string;
	}

#if LOG4CXX_HAS_PTHREAD_SELF && !(defined(_WIN32) && defined(_LIBCPP_VERSION))
	// pthread_t encoded in HEX takes needs as many characters
	// as two times the size of the type, plus an additional null byte.
	auto threadId = pthread_self();
	char result[sizeof(pthread_t) * 3 + 10];
	apr_snprintf(result, sizeof(result), LOG4CXX_APR_THREAD_FMTSPEC, (void*) &threadId);
	thread_id_string = Transcoder::decode(result);
#elif defined(_WIN32)
	char result[20];
	apr_snprintf(result, sizeof(result), LOG4CXX_WIN32_THREAD_FMTSPEC, GetCurrentThreadId());
	thread_id_string = Transcoder::decode(result);
#else
	std::stringstream ss;
	ss << std::hex << "0x" << std::this_thread::get_id();
	thread_id_string = Transcoder::decode(ss.str().c_str());
#endif
	return thread_id_string;
}

const LogString& LoggingEvent::getCurrentThreadUserName()
{
	LogString& thread_name = ThreadSpecificData::getThreadName();
	if( !thread_name.empty() ){
		return thread_name;
	}

#if LOG4CXX_HAS_PTHREAD_GETNAME && !(defined(_WIN32) && defined(_LIBCPP_VERSION))
	char result[16];
	pthread_t current_thread = pthread_self();
	if (pthread_getname_np(current_thread, result, sizeof(result)) < 0 || 0 == result[0])
		thread_name = getCurrentThreadName();
	else
		thread_name = Transcoder::decode(result);
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
			thread_name = decoded;
		}
	}
	if (thread_name.empty())
		thread_name = getCurrentThreadName();
#else
	thread_name = getCurrentThreadName();
#endif
	return thread_name;
}

void LoggingEvent::setProperty(const LogString& key, const LogString& value)
{
	if (m_priv->properties == 0)
	{
		m_priv->properties = new std::map<LogString, LogString>;
	}

	(*m_priv->properties)[key] = value;
}

const LevelPtr& LoggingEvent::getLevel() const
{
	return m_priv->level;
}

const LogString& LoggingEvent::getLoggerName() const
{
	return m_priv->logger;
}

const LogString& LoggingEvent::getMessage() const
{
	return m_priv->message;
}

const LogString& LoggingEvent::getRenderedMessage() const
{
	return m_priv->message;
}

const LogString& LoggingEvent::getThreadName() const
{
	return m_priv->threadName;
}

log4cxx_time_t LoggingEvent::getTimeStamp() const
{
	return m_priv->timeStamp;
}

const LOG4CXX_NS::spi::LocationInfo& LoggingEvent::getLocationInformation() const
{
	return m_priv->locationInfo;
}

std::chrono::time_point<std::chrono::system_clock> LoggingEvent::getChronoTimeStamp() const{
	return m_priv->chronoTimeStamp;
}

