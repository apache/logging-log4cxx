/***************************************************************************
              levelrangefilter.cpp  -  class LevelRangeFilter
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

#include <log4cxx/varia/levelrangefilter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::varia;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(LevelRangeFilter)

String LevelRangeFilter::LEVEL_MIN_OPTION = _T("LevelMin");
String LevelRangeFilter::LEVEL_MAX_OPTION = _T("LevelMax");
String LevelRangeFilter::ACCEPT_ON_MATCH_OPTION = _T("AcceptOnMatch");

LevelRangeFilter::LevelRangeFilter()
: acceptOnMatch(true), levelMin(&Level::ALL), levelMax(&Level::OFF)
{
}

void LevelRangeFilter::setOption(const String& option,
	const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, LEVEL_MIN_OPTION))
	{
		levelMin = &Level::toLevel(value, *levelMin);
	}
else if (StringHelper::equalsIgnoreCase(option, LEVEL_MAX_OPTION))
	{
		levelMax = &Level::toLevel(value, *levelMax);
	}
	else if (StringHelper::equalsIgnoreCase(option, ACCEPT_ON_MATCH_OPTION))
	{
		acceptOnMatch = OptionConverter::toBoolean(value, acceptOnMatch);
	}
}

Filter::FilterDecision LevelRangeFilter::decide(
	const log4cxx::spi::LoggingEvent& event)
{
	if (!event.getLevel().isGreaterOrEqual(*levelMin))
	{
		// level of event is less than minimum
		return Filter::DENY;
	}

	if (event.getLevel().toInt() > levelMax->toInt())
	{
		// level of event is greater than maximum
		// Alas, there is no Level.isGreater method. and using
		// a combo of isGreaterOrEqual && !Equal seems worse than
		// checking the int values of the level objects..
		return Filter::DENY;
	}

	if (acceptOnMatch)
	{
		// this filter set up to bypass later filters and always return
		// accept if level in range
		return Filter::ACCEPT;
	}
	else
	{
		// event is ok for this filter; allow later filters to have a look..
		return Filter::NEUTRAL;
	}
}

