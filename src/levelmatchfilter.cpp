/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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


LevelMatchFilter::LevelMatchFilter()
: acceptOnMatch(true)
{
}

void LevelMatchFilter::setOption(const LogString& option,
	const LogString& value)
{


	if (StringHelper::equalsIgnoreCase(option,
             LOG4CXX_STR("LEVELTOMATCH"), LOG4CXX_STR("leveltomatch")))
	{
		setLevelToMatch(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
             LOG4CXX_STR("ACCEPTONMATCH"), LOG4CXX_STR("acceptonmatch")))
	{
		acceptOnMatch = OptionConverter::toBoolean(value, acceptOnMatch);
	}
}

void LevelMatchFilter::setLevelToMatch(const LogString& levelToMatch)
{
	this->levelToMatch = OptionConverter::toLevel(levelToMatch, this->levelToMatch);
}

const LogString& LevelMatchFilter::getLevelToMatch() const
{
	return levelToMatch->toString();
}

Filter::FilterDecision LevelMatchFilter::decide(
	const log4cxx::spi::LoggingEventPtr& event) const
{
	if(levelToMatch != 0 && levelToMatch->equals(event->getLevel()))
	{
		if(acceptOnMatch)
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

