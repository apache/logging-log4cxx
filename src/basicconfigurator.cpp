/***************************************************************************
              basicconfigurator.h  -  BasicConfigurator
                             -------------------
    begin                : 06/19/2003
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

#include <log4cxx/basicconfigurator.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/logger.h>

using namespace log4cxx;

void BasicConfigurator::configure()
{
	LoggerPtr root = Logger::getRootLogger();
	root->addAppender(new ConsoleAppender(
		new PatternLayout(PatternLayout::TTCC_CONVERSION_PATTERN)));
}

void BasicConfigurator::configure(const AppenderPtr& appender)
{
	LoggerPtr root = Logger::getRootLogger();
	root->addAppender(appender);
}

void BasicConfigurator::resetConfiguration()
{
	LogManager::resetConfiguration();
}
