/***************************************************************************
                          logmanager.cpp  -  class LogManager
                             -------------------
    begin                : jeu avr 17 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/logmanager.h>
#include <log4cxx/spi/defaultrepositoryselector.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/spi/rootcategory.h>
#include <log4cxx/spi/loggerfactory.h>
#include <stdexcept>
#include <log4cxx/level.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(DefaultRepositorySelector)

void * LogManager::guard = 0;
RepositorySelectorPtr LogManager::repositorySelector =
	  new DefaultRepositorySelector(
		  new Hierarchy(
			  new RootCategory(Level::DEBUG)));


void LogManager::setRepositorySelector(spi::RepositorySelectorPtr selector,
	void * guard)
{
	if((LogManager::guard != 0) && (LogManager::guard != guard))
	{
		throw IllegalArgumentException(
		_T("Attempted to reset the LoggerFactory without possessing the guard."));
	}

	if(selector == 0)
	{
		throw IllegalArgumentException(
		_T("RepositorySelector must be non-null."));
	}

	LogManager::guard = guard;
	LogManager::repositorySelector = selector;
}

LoggerRepositoryPtr LogManager::getLoggerRepository()
{
	return repositorySelector->getLoggerRepository();
}

LoggerPtr LogManager::getRootLogger()
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	return repositorySelector->getLoggerRepository()->getRootLogger();
}

/**
Retrieve the appropriate Logger instance.
*/
LoggerPtr LogManager::getLogger(const tstring& name)
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	return repositorySelector->getLoggerRepository()->getLogger(name);
}

/**
Retrieve the appropriate Logger instance.
*/
LoggerPtr LogManager::getLogger(const tstring& name,
								spi::LoggerFactoryPtr factory)
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	return repositorySelector->getLoggerRepository()->getLogger(name, factory);
}

LoggerPtr LogManager::exists(const tstring& name)
{
	return repositorySelector->getLoggerRepository()->exists(name);
}

LoggerList LogManager::getCurrentLoggers()
{
	return repositorySelector->getLoggerRepository()->getCurrentLoggers();
}

void LogManager::shutdown()
{
	repositorySelector->getLoggerRepository()->shutdown();
}

void LogManager::resetConfiguration()
{
	repositorySelector->getLoggerRepository()->resetConfiguration();
}

 
