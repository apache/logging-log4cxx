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
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/helpers/optional.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

struct LoggingEvent::LoggingEventPrivate
{
	LoggingEventPrivate(const ThreadSpecificData::NamePairPtr p = ThreadSpecificData::getNames()) :
		timeStamp(0),
#if LOG4CXX_ABI_VERSION <= 15
		threadName(p->idString),
		threadUserName(p->threadName),
#endif
		pNames(p)
	{
	}

	LoggingEventPrivate
		( const LogString& logger1
		, const LevelPtr& level1
		, const LocationInfo& locationInfo1
		, LogString&& message1
		, const ThreadSpecificData::NamePairPtr p = ThreadSpecificData::getNames()
		) :
		logger(logger1),
		level(level1),
		message(std::move(message1)),
		timeStamp(Date::currentTime()),
		locationInfo(locationInfo1),
#if LOG4CXX_ABI_VERSION <= 15
		threadName(p->idString),
		threadUserName(p->threadName),
#endif
		chronoTimeStamp(std::chrono::microseconds(timeStamp)),
		pNames(p)
	{
	}

	LoggingEventPrivate(
		const LogString& logger1, const LevelPtr& level1,
		const LogString& message1, const LocationInfo& locationInfo1,
		const ThreadSpecificData::NamePairPtr& p = ThreadSpecificData::getNames()
		) :
		logger(logger1),
		level(level1),
		message(message1),
		timeStamp(Date::currentTime()),
		locationInfo(locationInfo1),
#if LOG4CXX_ABI_VERSION <= 15
		threadName(p->idString),
		threadUserName(p->threadName),
#endif
		chronoTimeStamp(std::chrono::microseconds(timeStamp)),
		pNames(p)
	{
	}

	~LoggingEventPrivate()
	{
		delete properties;
	}

	/**
	* The name of the logger used to make the logging request
	**/
	LogString logger;

	/** severity level of logging event. */
	LevelPtr level;

#if LOG4CXX_ABI_VERSION <= 15
	mutable LogString* ndc{NULL};

	mutable MDC::Map* mdcCopy{NULL};
#endif

	/**
	* A map of String keys and String values.
	*/
	std::map<LogString, LogString>* properties{NULL};

#if LOG4CXX_ABI_VERSION <= 15
	mutable bool ndcLookupRequired{false};

	mutable bool mdcCopyLookupRequired{false};
#endif

	/** The application supplied message. */
	LogString message;


	/** The number of microseconds elapsed since 1970-01-01
	 *  at the time this logging event was created.
	 */
	log4cxx_time_t timeStamp;

	/** The source code location where the logging request was made. */
	const spi::LocationInfo locationInfo;


#if LOG4CXX_ABI_VERSION <= 15
	const LogString& threadName;

	const LogString& threadUserName;
#endif

	std::chrono::time_point<std::chrono::system_clock> chronoTimeStamp;

	/**
	 *  Thread names that remain valid for the lifetime of this LoggingEvent
	 *  (i.e. even after thread termination).
	 */
	ThreadSpecificData::NamePairPtr pNames;

	struct DiagnosticContext
	{
		Optional<NDC::DiagnosticContext> ctx;
		MDC::Map map;
	};
	/**
	 *  Used to hold the diagnostic context when the lifetime
	 *  of this LoggingEvent exceeds the duration of the logging request.
	 */
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
	return m_priv->pNames->threadName;
}

bool LoggingEvent::getNDC(LogString& dest) const
{
	bool result = false;
	// Use the copy of the diagnostic context if it exists.
	// Otherwise use the NDC that is associated with the thread.
	if (m_priv->dc)
	{
		result = bool(m_priv->dc->ctx);
		if (result)
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
	else if (auto pData = ThreadSpecificData::getCurrentData())
	{
		for (auto const& item : pData->getMap())
			result.push_back(item.first);
	}
	return result;
}

void LoggingEvent::LoadDC() const
{
	m_priv->dc = std::make_unique<LoggingEventPrivate::DiagnosticContext>();
	if (auto pData = ThreadSpecificData::getCurrentData())
	{
		m_priv->dc->map = pData->getMap();
		auto& stack = pData->getStack();
		if (!stack.empty())
			m_priv->dc->ctx = stack.top();
	}
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
	return m_priv->pNames->idString;
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

