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

#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/appender.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/spi/loggerrepository.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(Logger)

String Logger::FQCN = Logger::getStaticClass().getName();

Logger::Logger(const String& name)
: name(name), level(Level::OFF), additive(true), repository(0)
{
}

Logger::~Logger()
{
}

void Logger::addAppender(AppenderPtr newAppender)
{
	synchronized sync(this);

	if (aai == 0)
	{
		  aai = new AppenderAttachableImpl();
	}
	aai->addAppender(newAppender);
	repository->fireAddAppenderEvent(this, newAppender);
}


void Logger::assertLog(bool assertion, const String& msg)
{
	if(!assertion)
	{
		this->error(msg);
	}
}

void Logger::callAppenders(const spi::LoggingEventPtr& event)
{
	int writes = 0;

	for(LoggerPtr logger = this; logger != 0; logger = logger->parent)
	{
		// Protected against simultaneous call to addAppender, removeAppender,...
		synchronized sync(logger);

		if (logger->aai != 0)
		{
			writes += logger->aai->appendLoopOnAppenders(event);
		}
		
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

void Logger::debug(const String& message, const char* file, int line)
{
	if(repository->isDisabled(Level::DEBUG_INT))
	{
		return;
	}
	
	if(Level::DEBUG->isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(FQCN, Level::DEBUG, message, file, line);
	}
}

void Logger::error(const String& message, const char* file, int line)
{
	if(repository->isDisabled(Level::ERROR_INT))
	{
		return;
	}

	if(Level::ERROR->isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(FQCN, Level::ERROR, message, file, line);
	}
}

void Logger::fatal(const String& message, const char* file, int line)
{
	if(repository->isDisabled(Level::FATAL_INT))
	{
		return;
	}

	if(Level::FATAL->isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(FQCN, Level::FATAL, message, file, line);
	}
}

void Logger::forcedLog(const String& fqcn, const LevelPtr& level, const String& message,
			const char* file, int line)
{
	callAppenders(new LoggingEvent(fqcn, this, level, message, file, line));
}

bool Logger::getAdditivity()
{
	return additive;
}

AppenderList Logger::getAllAppenders()
{
	synchronized sync(this);

	if (aai == 0)
	{
		return AppenderList();
	}
	else
	{
		return aai->getAllAppenders();
	}
}

AppenderPtr Logger::getAppender(const String& name)
{
	synchronized sync(this);

	if (aai == 0 || name.empty())
	{
		return 0;
	}
	
	return aai->getAppender(name);
}

const LevelPtr& Logger::getEffectiveLevel()
{
	for(Logger * l = this; l != 0; l=l->parent)
	{
		if(l->level != Level::OFF)
		{
			return l->level;
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

const LevelPtr& Logger::getLevel()
{
	return level;
}

void Logger::info(const String& message, const char* file, int line)
{
	if(repository->isDisabled(Level::INFO_INT))
	{
		return;
	}

	if(Level::INFO->isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(FQCN, Level::INFO, message, file, line);
	}
}

bool Logger::isAttached(AppenderPtr appender)
{
	synchronized sync(this);

	if (appender == 0 || aai == 0)
	{
		return false;
	}
	else
	{
		return aai->isAttached(appender);
	}
}

bool Logger::isDebugEnabled()
{
	if(repository->isDisabled(Level::DEBUG_INT))
	{
		return false;
	}
	
	return Level::DEBUG->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isEnabledFor(const LevelPtr& level)
{
	if(repository->isDisabled(level->level))
	{
		return false;
	}
	
	return level->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isInfoEnabled()
{
	if(repository->isDisabled(Level::INFO_INT))
	{
		return false;
	}

	return Level::INFO->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isErrorEnabled()
{
	if(repository->isDisabled(Level::ERROR_INT))
	{
		return false;
	}

	return Level::ERROR->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isWarnEnabled()
{
	if(repository->isDisabled(Level::WARN_INT))
	{
		return false;
	}

	return Level::WARN->isGreaterOrEqual(getEffectiveLevel());
}

bool Logger::isFatalEnabled()
{
	if(repository->isDisabled(Level::FATAL_INT))
	{
		return false;
	}

	return Level::FATAL->isGreaterOrEqual(getEffectiveLevel());
}

void Logger::log(const LevelPtr& level, const String& message,
	const char* file, int line)
{

	if(repository->isDisabled(level->level))
	{
		return;
	}
	if(level->isGreaterOrEqual(getEffectiveLevel()))
	{
		forcedLog(FQCN, level, message, file, line);
	}

}

void Logger::removeAllAppenders() 
{
	synchronized sync(this);
	
	if(aai != 0)
	{
		aai->removeAllAppenders();
		aai = 0;
	}
}

void Logger::removeAppender(AppenderPtr appender)
{
	synchronized sync(this);

	if(appender == 0 || aai == 0)
	{
		return;
	}

	aai->removeAppender(appender);
}

void Logger::removeAppender(const String& name) 
{
	synchronized sync(this);

	if(name.empty() || aai == 0)
	{
		return;
	}

	aai->removeAppender(name);
}

void Logger::setAdditivity(bool additive)
{
	this->additive = additive;
}

void Logger::setHierarchy(spi::LoggerRepository * repository)
{
	this->repository = repository;
}

void Logger::setLevel(const LevelPtr& level)
{
	this->level = level;
}

void Logger::warn(const String& message, const char* file, int line)
{
	if(repository->isDisabled(Level::WARN_INT))
	{
		return;
	}

	if(Level::WARN->isGreaterOrEqual(getEffectiveLevel()))
	{
		 forcedLog(FQCN, Level::WARN, message, file, line);
	}
}


LoggerPtr Logger::getLogger(const String& name)
{
	return LogManager::getLogger(name);
}

LoggerPtr Logger::getRootLogger() {
	return LogManager::getRootLogger();
}

LoggerPtr Logger::getLogger(const String& name,
							spi::LoggerFactoryPtr factory)
{
	return LogManager::getLogger(name, factory);
}
