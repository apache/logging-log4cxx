/***************************************************************************
                                 xlogger.cpp
                             -------------------
    begin                : 2003/12/02
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include "xlogger.h"
#include <log4cxx/level.h>
#include <log4cxx/logmanager.h>

using namespace log4cxx;

IMPLEMENT_LOG4CXX_OBJECT(XLogger)
IMPLEMENT_LOG4CXX_OBJECT(XFactory)

String XLogger::FQCN = XLogger::getStaticClass().getName() + _T(".");
XFactoryPtr XLogger::factory = new XFactory();

void XLogger::debug(const String& message, const char* file, int line)
{
	if (repository->isDisabled(Level::DEBUG_INT))
	{
		return;
	}

	if (XLevel::LETHAL->isGreaterOrEqual(this->getEffectiveLevel()))
	{
		forcedLog(FQCN, Level::getDebugLevel(), message + _T(" ") + suffix, file,line);
	}
}

void XLogger::lethal(const String& message, const char* file, int line)
{
	if (repository->isDisabled(XLevel::LETHAL_INT))
	{
		return;
	}

	if (XLevel::LETHAL->isGreaterOrEqual(this->getEffectiveLevel()))
	{
		forcedLog(FQCN, XLevel::LETHAL, message, file,line);
	}
}

void XLogger::lethal(const String& message)
{
	if (repository->isDisabled(XLevel::LETHAL_INT))
	{
		return;
	}

	if (XLevel::LETHAL->isGreaterOrEqual(this->getEffectiveLevel()))
	{
		forcedLog(FQCN, XLevel::LETHAL, message);
	}
}

LoggerPtr XLogger::getLogger(const String& name)
{
	return LogManager::getLogger(name, factory);
}

LoggerPtr XLogger::getLogger(const helpers::Class& clazz)
{
	return XLogger::getLogger(clazz.getName());
}

void XLogger::trace(const String& message, const char* file, int line)
{
	if (repository->isDisabled(XLevel::TRACE_INT))
	{
		return;
	}

	if (XLevel::TRACE->isGreaterOrEqual(this->getEffectiveLevel()))
	{
		forcedLog(FQCN, XLevel::TRACE, message, file, line);
	}
}

void XLogger::trace(const String& message)
{
	if (repository->isDisabled(XLevel::TRACE_INT))
	{
		return;
	}

	if (XLevel::TRACE->isGreaterOrEqual(this->getEffectiveLevel()))
	{
		forcedLog(FQCN, XLevel::TRACE, message);
	}
}

XFactory::XFactory()
{
}

LoggerPtr XFactory::makeNewLoggerInstance(const String& name)
{
	return new XLogger(name);
}
