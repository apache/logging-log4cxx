/***************************************************************************
                          appenderattachableimpl.cpp  -  description
                             -------------------
    begin                : mer avr 16 2003
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

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/appender.h>
#include <log4cxx/helpers/appenderattachableimpl.h>
#include <log4cxx/spi/loggingevent.h>
#include <algorithm>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(AppenderAttachableImpl)

void AppenderAttachableImpl::addAppender(AppenderPtr newAppender)
{
    // Null values for newAppender parameter are strictly forbidden.
    if(newAppender == 0)
    {
        return;
    }

    AppenderList::iterator it = std::find(
        appenderList.begin(), appenderList.end(), newAppender);

    if (it == appenderList.end())
    {
        appenderList.push_back(newAppender);
    }
}

int AppenderAttachableImpl::appendLoopOnAppenders(const spi::LoggingEventPtr& event)
{
    AppenderList::iterator it, itEnd = appenderList.end();
    AppenderPtr appender;
    for(it = appenderList.begin(); it != itEnd; it++)
    {
        appender = *it;
        appender->doAppend(event);
    }

	return appenderList.size();
}

AppenderList AppenderAttachableImpl::getAllAppenders()
{
    return appenderList;
}

AppenderPtr AppenderAttachableImpl::getAppender(const String& name)
{
	if (name.empty())
	{
		return 0;
	}

	AppenderList::iterator it, itEnd = appenderList.end();
	AppenderPtr appender;
	for(it = appenderList.begin(); it != itEnd; it++)
	{
		appender = *it;
		if(name == appender->getName())
		{
			return appender;
		}
	}
	
	return 0;
}

bool AppenderAttachableImpl::isAttached(AppenderPtr appender)
{
	if (appender == 0)
    {
        return false;
    }

    AppenderList::iterator it = std::find(
        appenderList.begin(), appenderList.end(), appender);

    return it != appenderList.end();
}

void AppenderAttachableImpl::removeAllAppenders()
{
    AppenderList::iterator it, itEnd = appenderList.end();
    AppenderPtr a;
    for(it = appenderList.begin(); it != itEnd; it++)
    {
        a = *it;
        a->close();
    }
     
    appenderList.clear();
}

void AppenderAttachableImpl::removeAppender(AppenderPtr appender)
{
    if (appender == 0)
        return;
        
    AppenderList::iterator it = std::find(
        appenderList.begin(), appenderList.end(), appender);

    if (it != appenderList.end())
    {
        appenderList.erase(it);
    }
}

void AppenderAttachableImpl::removeAppender(const String& name)
{
	if (name.empty())
	{
		return;
	}

	AppenderList::iterator it, itEnd = appenderList.end();
	AppenderPtr appender;
	for(it = appenderList.begin(); it != itEnd; it++)
	{
		appender = *it;
		if(name == appender->getName())
		{
			appenderList.erase(it);
			return;
		}
	}
}
