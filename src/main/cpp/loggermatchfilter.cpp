/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/logstring.h>
#include <log4cxx/filter/loggermatchfilter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/private/filter_priv.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::filter;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

#define priv static_cast<LoggerMatchFilterPrivate*>(m_priv.get())

struct LoggerMatchFilter::LoggerMatchFilterPrivate : public FilterPrivate
{
	LoggerMatchFilterPrivate() : FilterPrivate(),
		acceptOnMatch(true),
		loggerToMatch(LOG4CXX_STR("root")) {}

	bool acceptOnMatch;
	LogString loggerToMatch;
};

IMPLEMENT_LOG4CXX_OBJECT(LoggerMatchFilter)


LoggerMatchFilter::LoggerMatchFilter()
	: Filter(std::make_unique<LoggerMatchFilterPrivate>())
{
}

LoggerMatchFilter::~LoggerMatchFilter() {}

void LoggerMatchFilter::setLoggerToMatch(const LogString& value)
{
	priv->loggerToMatch = value;
}

LogString LoggerMatchFilter::getLoggerToMatch() const
{
	return priv->loggerToMatch;
}

void LoggerMatchFilter::setOption(const LogString& option,
	const LogString& value)
{

	if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("LOGGERTOMATCH"), LOG4CXX_STR("loggertomatch")))
	{
		setLoggerToMatch(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("ACCEPTONMATCH"), LOG4CXX_STR("acceptonmatch")))
	{
		priv->acceptOnMatch = OptionConverter::toBoolean(value, priv->acceptOnMatch);
	}
}

Filter::FilterDecision LoggerMatchFilter::decide(
	const spi::LoggingEventPtr& event) const
{
	bool matchOccured = priv->loggerToMatch == event->getLoggerName();

	if (matchOccured)
	{
		if (priv->acceptOnMatch)
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

void LoggerMatchFilter::setAcceptOnMatch(bool acceptOnMatch1)
{
	priv->acceptOnMatch = acceptOnMatch1;
}

bool LoggerMatchFilter::getAcceptOnMatch() const
{
	return priv->acceptOnMatch;
}
