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

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

// time at startup
time_t LoggingEvent::startTime = time(0);

LoggingEvent::LoggingEvent()
: timeStamp(0), level(&Level::OFF), ndcLookupRequired(true), line(0)
{
}

LoggingEvent::LoggingEvent(const LoggerPtr& logger, const Level& level,
	const tstring& message, const char* file, int line)
: logger(logger), level(&level), message(message), file((char*)file), 
line(line), timeStamp(time(0)), ndcLookupRequired(true)
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

void LoggingEvent::write(helpers::SocketOutputStreamPtr os) const
{
	tstring::size_type size;
	
	// name
	os->write(logger->getName());

	// level
	os->write(level->toInt());

	// message
	os->write(message);

	// timeStamp
	os->write(timeStamp);

	// line
	os->write(line);

	// ndc
	os->write(getNDC());

	// threadId
	os->write(threadId);
}

void LoggingEvent::read(helpers::SocketInputStreamPtr is)
{
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
	is->read(timeStamp);

	// file
	file = 0;

	// line
	is->read(line);

	// ndc
	is->read(ndc);

	// threadId
	is->read(threadId);
}

LoggingEvent * LoggingEvent::copy() const
{
	return new LoggingEvent(*this);
}



