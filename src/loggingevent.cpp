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

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

// time at startup
long long LoggingEvent::startTime = System::currentTimeMillis();

LoggingEvent::LoggingEvent()
: timeStamp(0), level(&Level::OFF), ndcLookupRequired(true), line(0),
mdcCopyLookupRequired(true)
{
}

LoggingEvent::LoggingEvent(const tstring& fqnOfCategoryClass,
	const LoggerPtr& logger, const Level& level,
	const tstring& message, const char* file, int line)
: fqnOfCategoryClass(fqnOfCategoryClass), logger(logger), level(&level),
message(message), file((char*)file), line(line),
timeStamp(System::currentTimeMillis()), ndcLookupRequired(true)
{
	threadId = Thread::getCurrentThreadId();
}

LoggingEvent::LoggingEvent(const LoggingEvent& event)
: logger(event.logger), level(event.level), message(event.message),
file(event.file), line(event.line), timeStamp(event.timeStamp),
ndcLookupRequired(event.ndcLookupRequired), ndc(event.ndc),
threadId(event.threadId)
{
}

const tstring& LoggingEvent::getNDC() const
{
	if(ndcLookupRequired)
	{
		((LoggingEvent *)this)->ndcLookupRequired = false;
		((LoggingEvent *)this)->ndc = NDC::get();
	}

	return ndc;
}

tstring LoggingEvent::getMDC(const tstring& key) const
{
   // Note the mdcCopy is used if it exists. Otherwise we use the MDC
    // that is associated with the thread.
    if (!mdcCopy.empty())
	{
		MDC::Map::const_iterator it = mdcCopy.find(key);

		if (it != mdcCopy.end())
		{
			tstring r = it->second;

			if (!r.empty())
			{
				return r;
			}
		}
    }

    return MDC::get(key);

}

std::set<tstring> LoggingEvent::getMDCKeySet() const
{
	std::set<tstring> set;

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

tstring LoggingEvent::getProperty(const tstring& key) const
{
	std::map<tstring, tstring>::const_iterator  it = properties.find(key);

	if (it != properties.end())
	{
		const tstring& p = it->second;

		if (!p.empty())
		{
			return p;
		}
	}

	return tstring();
}

std::set<tstring> LoggingEvent::getPropertyKeySet() const
{
	std::set<tstring> set;
	std::map<tstring, tstring>::const_iterator it;
	for (it = properties.begin(); it != properties.end(); it++)
	{
		set.insert(it->first);
	}

	return set;
}

void LoggingEvent::setProperty(const tstring& key, const tstring& value)
{
	properties[key] = value;
}

void LoggingEvent::write(helpers::SocketOutputStreamPtr os) const
{
	// fqnOfCategoryClass
	os->write(fqnOfCategoryClass);

	// name
	os->write(logger->getName());

	// level
	os->write(level->toInt());

	// message
	os->write(message);

	// timeStamp
	os->write(&timeStamp, sizeof(timeStamp));

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
	std::map<tstring, tstring>::const_iterator it2;
	for (it2 = properties.begin(); it2 != properties.end(); it2++)
	{
		os->write(it2->first);
		os->write(it2->second);
	}

	// threadId
	os->write(threadId);
}

void LoggingEvent::read(helpers::SocketInputStreamPtr is)
{
	// fqnOfCategoryClass
	is->read(fqnOfCategoryClass);

	// name
	tstring name;
	is->read(name);
	logger = Logger::getLogger(name);

	// level
	int levelInt;
	is->read(levelInt);
	level = &Level::toLevel(levelInt);

	// message
	is->read(message);

	// timeStamp
	is->read(&timeStamp, sizeof(timeStamp));

	// file
	file = 0;

	// line
	is->read(line);

	// ndc
	is->read(ndc);

	// mdc
	tstring key, value;
	int n, size;
	is->read(size);
	for (n = 0; n < size; n++)
	{
		is->read(key);
		is->read(value);
		mdcCopy[key] = value;
	}

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

LoggingEvent * LoggingEvent::copy() const
{
	return new LoggingEvent(*this);
}

