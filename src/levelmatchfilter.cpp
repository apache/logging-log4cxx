/***************************************************************************
              levelmatchfilter.cpp  -  class LevelMatchFilter
                             -------------------
    begin                : dim mai 18 2003
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

#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/varia/levelmatchfilter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::varia;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(LevelMatchFilter)

String LevelMatchFilter::LEVEL_TO_MATCH_OPTION = _T("LevelToMatch");
String LevelMatchFilter::ACCEPT_ON_MATCH_OPTION = _T("AcceptOnMatch");

LevelMatchFilter::LevelMatchFilter()
: acceptOnMatch(true), levelToMatch(Level::OFF)
{
}

void LevelMatchFilter::setOption(const String& option,
	const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, LEVEL_TO_MATCH_OPTION))
	{
		setLevelToMatch(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, ACCEPT_ON_MATCH_OPTION))
	{
		acceptOnMatch = OptionConverter::toBoolean(value, acceptOnMatch);
	}
}

void LevelMatchFilter::setLevelToMatch(const String& levelToMatch)
{
	this->levelToMatch = OptionConverter::toLevel(levelToMatch, this->levelToMatch);
}

const String& LevelMatchFilter::getLevelToMatch() const
{
	return levelToMatch->toString();
}
  
Filter::FilterDecision LevelMatchFilter::decide(
	const log4cxx::spi::LoggingEventPtr& event)
{
	if(this->levelToMatch->equals(event->getLevel()))
	{
		if(this->acceptOnMatch)
		{
			return Filter::ACCEPT;
		}
		else
		{
			return Filter::DENY;
		}
	}
	else
	{
		return Filter::NEUTRAL;
	}
}

