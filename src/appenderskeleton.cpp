/***************************************************************************
                          appenderskeleton.cpp  -  AppenderSkeleton
                             -------------------
    begin                : mar avr 15 2003
    copyright            : (C) 2003 by michael
    email                : michael@montmartre-2-81-57-89-54.fbx.proxad.net
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/onlyonceerrorhandler.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

AppenderSkeleton::AppenderSkeleton()
: errorHandler(new OnlyOnceErrorHandler()), closed(false),
threshold(Level::ALL)
{
}

void AppenderSkeleton::finalize()
{
// An appender might be closed then garbage collected. There is no
// point in closing twice.
	if(closed)
	{
		return;
	}

	close();
}

void AppenderSkeleton::addFilter(spi::FilterPtr newFilter)
{
	if(headFilter == 0)
	{
		headFilter = tailFilter = newFilter;
	}
	else
	{
		tailFilter->next = newFilter;
		tailFilter = newFilter;
	}
}

void AppenderSkeleton::clearFilters()
{
	headFilter = tailFilter = 0;
}

bool AppenderSkeleton::isAsSevereAsThreshold(LevelPtr level)
{
	return ((level == 0) || level->isGreaterOrEqual(threshold));
}

void AppenderSkeleton::doAppend(const spi::LoggingEventPtr& event)
{
	synchronized sync(this);
	
	if(closed)
	{
		LogLog::error(_T("Attempted to append to closed appender named [")
			+name+_T("]."));
		return;
	}

	if(!isAsSevereAsThreshold(event->getLevel()))
	{
		return;
	}

	FilterPtr f = headFilter;


	while(f != 0)
	{
		 switch(f->decide(event))
		 {
			 case Filter::DENY:
				 return;
			 case Filter::ACCEPT:
				 f = 0;
				 break;
			 case Filter::NEUTRAL:
				 f = f->next;
		 }
	}

	append(event);
}

void AppenderSkeleton::setErrorHandler(spi::ErrorHandlerPtr errorHandler)
{
	synchronized sync(this);
	
	if(errorHandler == 0)
	{
		// We do not throw exception here since the cause is probably a
		// bad config file.
		LogLog::warn(_T("You have tried to set a null error-handler."));
	}
	else
	{
		this->errorHandler = errorHandler;
	}
}

void AppenderSkeleton::setThreshold(const LevelPtr& threshold)
{
	this->threshold = threshold;
}
