/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/ndc.h>

#include <log4cxx/level.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/socketinputstream.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/socket.h>
#include <log4cxx/helpers/aprinitializer.h>

#include <apr_time.h>
#include <apr_portable.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::spi::location;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(LoggingEvent)


//
//   Accessor for start time.
//     Called from LogManager::getRepositorySelector
//       to initialize APR and set "start" time.
//
log4cxx_time_t LoggingEvent::getStartTime() {
  log4cxx::helpers::APRInitializer::initialize();
  static apr_time_t startTime(apr_time_now());
  return startTime;
}

LoggingEvent::LoggingEvent()
: timeStamp(0), ndcLookupRequired(true), locationInfo(),
mdcCopyLookupRequired(true), properties(0)
{
}

LoggingEvent::LoggingEvent(
	const LoggerPtr& logger, const LevelPtr& level,
	const LogString& message, const LocationInfo& locationInfo)
: logger(logger), level(level),
message(message), locationInfo(locationInfo),
timeStamp(apr_time_now()), ndcLookupRequired(true),
mdcCopyLookupRequired(true), properties(0)
{
	apr_os_thread_t thread = apr_os_thread_current();
	threadId = (unsigned long) thread;
}

LoggingEvent::~LoggingEvent()
{
	if (properties != 0)
	{
		delete properties;
	}
}

const LogString& LoggingEvent::getLoggerName() const
{
	return logger->getName();
}

const LogString& LoggingEvent::getNDC() const
{
	if(ndcLookupRequired)
	{
		((LoggingEvent *)this)->ndcLookupRequired = false;
		((LoggingEvent *)this)->ndc = NDC::get();
	}

	return ndc;
}

LogString LoggingEvent::getMDC(const LogString& key) const
{
   // Note the mdcCopy is used if it exists. Otherwise we use the MDC
    // that is associated with the thread.
    if (!mdcCopy.empty())
	{
		MDC::Map::const_iterator it = mdcCopy.find(key);

		if (it != mdcCopy.end())
		{
			if (!it->second.empty())
			{
				return it->second;
			}
		}
    }

    return MDC::get(key);

}

std::set<LogString> LoggingEvent::getMDCKeySet() const
{
	std::set<LogString> set;

	if (!mdcCopy.empty())
	{
		MDC::Map::const_iterator it;
		for (it = mdcCopy.begin(); it != mdcCopy.end(); it++)
		{
			set.insert(it->first);

		}
	}
	else
	{
		MDC::Map m = MDC::getContext();

		MDC::Map::const_iterator it;
		for (it = m.begin(); it != m.end(); it++)
		{
			set.insert(it->first);
		}
	}

	return set;
}

void LoggingEvent::getMDCCopy() const
{
	if(mdcCopyLookupRequired)
	{
		((LoggingEvent *)this)->mdcCopyLookupRequired = false;
		// the clone call is required for asynchronous logging.
		((LoggingEvent *)this)->mdcCopy = MDC::getContext();
	}
}

LogString LoggingEvent::getProperty(const LogString& key) const
{
	if (properties == 0)
	{
		return LogString();
	}

	std::map<LogString, LogString>::const_iterator  it = properties->find(key);

	if (it != properties->end())
	{
		const LogString& p = it->second;

		if (!p.empty())
		{
			return p;
		}
	}

	return LogString();
}

std::set<LogString> LoggingEvent::getPropertyKeySet() const
{
	std::set<LogString> set;

	if (properties != 0)
	{
		std::map<LogString, LogString>::const_iterator it;
		for (it = properties->begin(); it != properties->end(); it++)
		{
			set.insert(it->first);
		}
	}

	return set;
}

void LoggingEvent::read(const helpers::SocketInputStreamPtr& is)
{
#if 0
	// fqnOfCategoryClass
	is->read(fqnOfCategoryClass);

	// name
	LogString name;
	is->read(name);
	logger = Logger::getLogger(name);

	// level
	readLevel(is);

	// message
	is->read(message);

	// timeStamp
	is->read(&timeStamp, sizeof(timeStamp));

	// file
	String buffer;
	is->read(buffer);

	if (!buffer.empty())
	{
		USES_CONVERSION;
		fileFromStream = T2A(buffer.c_str());
		file = (char *)fileFromStream.c_str();
	}

	// line
	is->read(line);

	// ndc
	is->read(ndc);
	ndcLookupRequired = false;

	// mdc
	String key, value;
	int n, size;
	is->read(size);
	for (n = 0; n < size; n++)
	{
		is->read(key);
		is->read(value);
		mdcCopy[key] = value;
	}
	mdcCopyLookupRequired = false;

	// properties
	is->read(size);
	for (n = 0; n < size; n++)
	{
		is->read(key);
		is->read(value);
		setProperty(key, value);
	}

	// threadId
	is->read(threadId);
#endif
}

void LoggingEvent::readLevel(const helpers::SocketInputStreamPtr& is)
{
  #if 0
	int levelInt;
	is->read(levelInt);

    String className;
	is->read(className);

	if (className.empty())
	{
		level = Level::toLevel(levelInt);
	}
	else try
	{
		Level::LevelClass& levelClass =
			(Level::LevelClass&)Loader::loadClass(className);
		level = levelClass.toLevel(levelInt);
	}
	catch (Exception& oops)
	{
		LogLog::warn(
			_T("Level deserialization failed, reverting to default."), oops);
		level = Level::toLevel(levelInt);
	}
	catch (...)
	{
		LogLog::warn(
			_T("Level deserialization failed, reverting to default."));
		level = Level::toLevel(levelInt);
	}
#endif
}

void LoggingEvent::setProperty(const LogString& key, const LogString& value)
{
	if (properties == 0)
	{
		properties = new std::map<LogString, LogString>;
	}

	(*properties)[key] = value;
}

void LoggingEvent::write(helpers::SocketOutputStreamPtr& os) const
{
  #if 0
	// fqnOfCategoryClass
	os->write(fqnOfCategoryClass);

	// name
	os->write(logger->getName());

	// level
	writeLevel(os);

	// message
	os->write(message);

	// timeStamp
	os->write(&timeStamp, sizeof(timeStamp));

	// file
	String buffer;
	if (file != 0)
	{
		USES_CONVERSION;
		buffer = A2T(file);
	}
	os->write(buffer);

	// line
	os->write(line);

	// ndc
	os->write(getNDC());

	// mdc
	getMDCCopy();
	os->write((int)mdcCopy.size());
	MDC::Map::const_iterator it;
	for (it = mdcCopy.begin(); it != mdcCopy.end(); it++)
	{
		os->write(it->first);
		os->write(it->second);
	}
> tests/src/nt/Makefile

	// properties
	int size = (properties != 0) ? (int)properties->size() : 0;
	os->write(size);

	if (size > 0)
	{
		std::map<String, String>::const_iterator it;
		for (it = properties->begin(); it != properties->end(); it++)
		{
			os->write(it->first);
			os->write(it->second);
		}
	}

	// threadId
	os->write(threadId);
#endif
}

void LoggingEvent::writeLevel(helpers::SocketOutputStreamPtr& os) const
{
#if 0
	os->write(level->toInt());

	const Class& clazz = level->getClass();

	if (&clazz == &Level::getStaticClass())
	{
		os->write(String());
	}
	else
	{
		os->write(clazz.getName());
	}
#endif
}

