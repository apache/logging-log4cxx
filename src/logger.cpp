/***************************************************************************
                          logger.cpp  -  class Logger
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

/*! \file logger.cpp Implementation of the class Logger. */

#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/appender.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(Logger)

Logger::Logger(const tstring& name)
: name(name), level(&Level::OFF), additive(true), repository(0)
{

}

Logger::~Logger()
{
}

void Logger::addAppender(AppenderPtr newAppender)
{
	AppenderAttachableImpl::addAppender(newAppender);
	repository->fireAddAppenderEvent(this, newAppender);
}


void Logger::assertLog(bool assertion, const tstring& msg)
{
	if(!assertion)
	{
		this->error(msg);
	}
}

void Logger::callAppenders(const spi::LoggingEvent& event)
{
	int writes = 0;

	for(LoggerPtr logger = this; logger != 0; logger = logger->parent)
	{
		writes += logger->appendLoopOnAppenders(event);

		if(!logger->additive)
		{
			break;
		}
	}

	if(writes == 0)
	{
		repository->emitNoAppenderWarning(this);
	}
}

void Logger::closeNestedAppenders()
{
	synchronized sync(this);

	
    AppenderList appenders = getAllAppenders();
    for(AppenderList::iterator it=appenders.begin(); it!=appenders.end(); ++it)
    {
        (*it)->close();
    }
}

void Logger::debug(const tstring& message, const char* file, int line)
{
	if(repository->isDisabled(Level::DEBUG_INT))
	{
		return;
	}
	
	if(Level::DEBUG.isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(Level::DEBUG, message, file, line);
	}
}

void Logger::error(const tstring& message, const char* file, int line)
{
	if(repository->isDisabled(Level::ERROR_INT))
	{
		return;
	}

	if(Level::ERROR.isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(Level::ERROR, message, file, line);
	}
}

void Logger::fatal(const tstring& message, const char* file, int line)
{
	if(repository->isDisabled(Level::FATAL_INT))
	{
		return;
	}

	if(Level::FATAL.isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(Level::FATAL, message, file, line);
	}
}

void Logger::forcedLog(const Level& level, const tstring& message,
			const char* file, int line)
{
	callAppenders(LoggingEvent(this, level, message, file, line));
}

bool Logger::getAdditivity()
{
	return additive;
}

const Level& Logger::getEffectiveLevel()
{
	for(Logger * l = this; l != 0; l=l->parent)
	{
		if(l->level != &Level::OFF)
		{
			return *l->level;
		}
	}

	return Level::OFF; // If reached will cause an NullPointerException.
}

LoggerRepositoryPtr Logger::getLoggerRepository()
{
	return repository;
}

LoggerPtr Logger::getParent()
{
	return parent;
}

const Level& Logger::getLevel()
{
	return *level;
}

void Logger::info(const tstring& message, const char* file, int line)
{
	if(repository->isDisabled(Level::INFO_INT))
	{
		return;
	}

	if(Level::INFO.isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(Level::INFO, message, file, line);
	}
}

bool Logger::isDebugEnabled()
{
	if(repository->isDisabled(Level::DEBUG_INT))
	{
		return false;
	}
	
	return Level::DEBUG.isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isEnabledFor(const Level& level)
{
	if(repository->isDisabled(level.level))
	{
		return false;
	}
	
	return level.isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isInfoEnabled()
{
	if(repository->isDisabled(Level::INFO_INT))
	{
		return false;
	}

	return Level::INFO.isGreaterOrEqual(getEffectiveLevel());

}

void Logger::log(const Level& level, const tstring& message,
	const char* file, int line)
{

	if(repository->isDisabled(level.level))
	{
		return;
	}
	if(level.isGreaterOrEqual(getEffectiveLevel()))
	{
		forcedLog(level, message, file, line);
	}

}

void Logger::setAdditivity(bool additive)
{
	this->additive = additive;
}

void Logger::setHierarchy(spi::LoggerRepository * repository)
{
	this->repository = repository;
}

void Logger::setLevel(const Level& level)
{
	this->level = &level;
}

void Logger::warn(const tstring& message, const char* file, int line)
{
	if(repository->isDisabled(Level::WARN_INT))
	{
		return;
	}

	if(Level::WARN.isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(Level::WARN, message, file, line);
	}
}


LoggerPtr Logger::getLogger(const tstring& name)
{
	return LogManager::getLogger(name);
}

LoggerPtr Logger::getRootLogger() {
	return LogManager::getRootLogger();
}

LoggerPtr Logger::getLogger(const tstring& name,
							spi::LoggerFactoryPtr factory)
{
	return LogManager::getLogger(name, factory);
}
