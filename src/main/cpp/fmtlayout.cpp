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
#include <log4cxx/fmtlayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>
#include <chrono>

#include <fmt/format.h>
#include <fmt/chrono.h>

using namespace log4cxx;
using namespace log4cxx::spi;

struct FMTLayout::FMTLayoutPrivate{
	FMTLayoutPrivate(){}

	FMTLayoutPrivate(const LogString& pattern) :
		conversionPattern(pattern)
	{}

	LogString conversionPattern;
};

IMPLEMENT_LOG4CXX_OBJECT(FMTLayout)

FMTLayout::FMTLayout() :
	m_priv(std::make_unique<FMTLayoutPrivate>())
{}

FMTLayout::FMTLayout(const LogString& pattern) :
	m_priv(std::make_unique<FMTLayoutPrivate>(pattern))
{}

FMTLayout::~FMTLayout(){}

void FMTLayout::setConversionPattern(const LogString& pattern)
{
	m_priv->conversionPattern = pattern;
	helpers::Pool pool;
	activateOptions(pool);
}

LogString FMTLayout::getConversionPattern() const
{
	return m_priv->conversionPattern;
}

void FMTLayout::setOption(const LogString& option, const LogString& value)
{
	if (helpers::StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("CONVERSIONPATTERN"),
			LOG4CXX_STR("conversionpattern")))
	{
		m_priv->conversionPattern = helpers::OptionConverter::convertSpecialChars(value);
	}
}

void FMTLayout::activateOptions(helpers::Pool&)
{

}

void FMTLayout::format(LogString& output,
	const spi::LoggingEventPtr& event,
	log4cxx::helpers::Pool&) const
{
	LogString locationFull = fmt::format("{}({})",
										 event->getLocationInformation().getFileName(),
										 event->getLocationInformation().getLineNumber());
	LogString ndc;
	event->getNDC(ndc);

	fmt::format_to(std::back_inserter(output),
				   m_priv->conversionPattern,
				   fmt::arg("d", event->getChronoTimeStamp()),
				   fmt::arg("c", event->getLoggerName()),
				   fmt::arg("logger", event->getLoggerName()),
				   fmt::arg("f", event->getLocationInformation().getShortFileName()),
				   fmt::arg("shortfilename", event->getLocationInformation().getShortFileName()),
				   fmt::arg("F", event->getLocationInformation().getFileName()),
				   fmt::arg("filename", event->getLocationInformation().getFileName()),
				   fmt::arg("l", locationFull),
				   fmt::arg("location", locationFull),
				   fmt::arg("L", event->getLocationInformation().getLineNumber()),
				   fmt::arg("line", event->getLocationInformation().getLineNumber()),
				   fmt::arg("m", event->getMessage()),
				   fmt::arg("message", event->getMessage()),
				   fmt::arg("M", event->getLocationInformation().getMethodName()),
				   fmt::arg("method", event->getLocationInformation().getMethodName()),
				   fmt::arg("n", LOG4CXX_EOL),
				   fmt::arg("newline", LOG4CXX_EOL),
				   fmt::arg("p", event->getLevel()->toString()),
				   fmt::arg("level", event->getLevel()->toString()),
				   fmt::arg("r", event->getTimeStamp()),
				   fmt::arg("t", event->getThreadName()),
				   fmt::arg("thread", event->getThreadName()),
				   fmt::arg("T", event->getThreadUserName()),
				   fmt::arg("threadname", event->getThreadUserName()),
				   fmt::arg("x", ndc),
				   fmt::arg("ndc", ndc)
				   );
}
