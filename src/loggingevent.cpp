/***************************************************************************
                          loggingevent.cpp  -  class LoggingEvent
                             -------------------
    begin                : mar avr 15 2003
    copyright            : (C) 2003 by michael
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/ndc.h>

#include <log4cxx/helpers/thread.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/socketoutputstream.h>
#include <log4cxx/helpers/socketinputstream.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/socket.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(LoggingEvent)

// time at startup
int64_t LoggingEvent::startTime = System::currentTimeMillis();

LoggingEvent::LoggingEvent()
: timeStamp(0), ndcLookupRequired(true), line(0),
mdcCopyLookupRequired(true)
{
}

LoggingEvent::LoggingEvent(const String& fqnOfCategoryClass,
	const LoggerPtr& logger, const LevelPtr& level,
	const String& message, const char* file, int line)
: fqnOfCategoryClass(fqnOfCategoryClass), logger(logger), level(level),
message(message), file((char*)file), line(line),
timeStamp(System::currentTimeMillis()), ndcLookupRequired(true),
mdcCopyLookupRequired(true)
{
	threadId = Thread::getCurrentThreadId();
}

const String& LoggingEvent::getLoggerName() const
{ 
	return logger->getName();
}

const String& LoggingEvent::getNDC() const
{
	if(ndcLookupRequired)
	{
		((LoggingEvent *)this)->ndcLookupRequired = false;
		((LoggingEvent *)this)->ndc = NDC::get();
	}

	return ndc;
}

String LoggingEvent::getMDC(const String& key) const
{
   // Note the mdcCopy is used if it exists. Otherwise we use the MDC
    // that is associated with the thread.
    if (!mdcCopy.empty())
	{
		MDC::Map::const_iterator it = mdcCopy.find(key);

		if (it != mdcCopy.end())
		{
			String r = it->second;

			if (!r.empty())
			{
				return r;
			}
		}
    }

    return MDC::get(key);

}

std::set<String> LoggingEvent::getMDCKeySet() const
{
	std::set<String> set;

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

String LoggingEvent::getProperty(const String& key) const
{
	std::map<String, String>::const_iterator  it = properties.find(key);

	if (it != properties.end())
	{
		const String& p = it->second;

		if (!p.empty())
		{
			return p;
		}
	}

	return String();
}

std::set<String> LoggingEvent::getPropertyKeySet() const
{
	std::set<String> set;
	std::map<String, String>::const_iterator it;
	for (it = properties.begin(); it != properties.end(); it++)
	{
		set.insert(it->first);
	}

	return set;
}

void LoggingEvent::read(const helpers::SocketInputStreamPtr& is)
{
	// fqnOfCategoryClass
	is->read(fqnOfCategoryClass);

	// name
	String name;
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
		properties[key] = value;
	}

	// threadId
	is->read(threadId);
}

void LoggingEvent::readLevel(const helpers::SocketInputStreamPtr& is)
{
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
}

void LoggingEvent::setProperty(const String& key, const String& value)
{
	properties[key] = value;
}

void LoggingEvent::write(helpers::SocketOutputStreamPtr& os) const
{
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

	// properties
	os->write((int)properties.size());
	std::map<String, String>::const_iterator it2;
	for (it2 = properties.begin(); it2 != properties.end(); it2++)
	{
		os->write(it2->first);
		os->write(it2->second);
	}

	// threadId
	os->write(threadId);
}

void LoggingEvent::writeLevel(helpers::SocketOutputStreamPtr& os) const
{
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
}


