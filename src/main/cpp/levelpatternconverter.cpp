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
#include <log4cxx/pattern/levelpatternconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/stringtokenizer.h>
#include <map>


using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::pattern;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(LevelPatternConverter)

namespace {
/**
 * Formats the level of a logging event using the labels,
 * maximum length and letter case requested in the conversion pattern
 */
class LevelLabelPatternConverter : public LevelPatternConverter
{
	public:
		/// The label to output for a level value
		using LabelMap = std::map<int, LogString>;

	private:
		const LabelMap m_labels;
		const size_t m_maxLength;
		const bool m_lowerCase;

	public:
		LevelLabelPatternConverter(const LabelMap& labels, size_t maxLength, bool lowerCase)
			: m_labels(labels)
			, m_maxLength(maxLength)
			, m_lowerCase(lowerCase)
			{}

		using LevelPatternConverter::format;

		// Output the label provided for the event's level, otherwise the (shortened) level name
		void format( const spi::LoggingEventPtr& event, LogString& toAppendTo ) const override
		{
			auto& level = event->getLevel();
			auto pLabel = m_labels.find(level->toInt());
			if (m_labels.end() != pLabel)
			{
				toAppendTo.append(pLabel->second);
				return;
			}
			auto name = level->toString();
			if (m_maxLength < name.length())
				name.erase(m_maxLength);
			if (m_lowerCase)
				name = StringHelper::toLowerCase(name);
			toAppendTo.append(name);
		}
};
}

LevelPatternConverter::LevelPatternConverter() :
	LoggingEventPatternConverter(LOG4CXX_STR("Level"),
		LOG4CXX_STR("level"))
{
}

PatternConverterPtr LevelPatternConverter::newInstance(
	const std::vector<LogString>& options)
{
	if (options.empty() || options.front().empty())
	{
		return std::make_shared<LevelPatternConverter>();
	}

	LevelLabelPatternConverter::LabelMap labels;
	size_t maxLength = LogString::npos;
	bool lowerCase = false;
	StringTokenizer items(options.front(), LOG4CXX_STR(","));
	while (items.hasMoreTokens())
	{
		auto item = items.nextToken();
		auto separator = item.find(0x3D /* '=' */);
		if (LogString::npos == separator)
		{
			LogLog::warn(LOG4CXX_STR("Ignoring level option [") + item
				+ LOG4CXX_STR("] which is not in the form name=value"));
			continue;
		}
		auto name = StringHelper::trim(item.substr(0, separator));
		auto value = StringHelper::trim(item.substr(separator + 1));
		if (StringHelper::equalsIgnoreCase(name, LOG4CXX_STR("LENGTH"), LOG4CXX_STR("length")))
		{
			int length = OptionConverter::toInt(value, 0);
			if (length <= 0)
				LogLog::warn(LOG4CXX_STR("Ignoring level length [") + value
					+ LOG4CXX_STR("] which is not a positive integer"));
			else
				maxLength = static_cast<size_t>(length);
		}
		else if (StringHelper::equalsIgnoreCase(name, LOG4CXX_STR("LOWERCASE"), LOG4CXX_STR("lowercase")))
		{
			lowerCase = OptionConverter::toBoolean(value, false);
		}
		else if (auto level = Level::toLevelLS(name, LevelPtr()))
		{
			labels[level->toInt()] = value;
		}
		else
		{
			LogLog::warn(LOG4CXX_STR("Ignoring label for unknown level [") + name + LOG4CXX_STR("]"));
		}
	}

	if (labels.empty() && LogString::npos == maxLength && !lowerCase)
	{
		return std::make_shared<LevelPatternConverter>();
	}
	return std::make_shared<LevelLabelPatternConverter>(labels, maxLength, lowerCase);
}

void LevelPatternConverter::format( const spi::LoggingEventPtr& event, LogString& toAppendTo ) const
{
	toAppendTo.append(event->getLevel()->toString());
}


/**
 * {@inheritDoc}
 */
LogString LevelPatternConverter::getStyleClass(const ObjectPtr& obj) const
{
	LoggingEventPtr e = LOG4CXX_NS::cast<LoggingEvent>(obj);

	if (e != NULL)
	{
		int lint = e->getLevel()->toInt();

		switch (lint)
		{
			case Level::TRACE_INT:
				return LOG4CXX_STR("level trace");

			case Level::DEBUG_INT:
				return LOG4CXX_STR("level debug");

			case Level::INFO_INT:
				return LOG4CXX_STR("level info");

			case Level::WARN_INT:
				return LOG4CXX_STR("level warn");

			case Level::ERROR_INT:
				return LOG4CXX_STR("level error");

			case Level::FATAL_INT:
				return LOG4CXX_STR("level fatal");

			default:
				return LogString(LOG4CXX_STR("level ")) + e->getLevel()->toString();
		}
	}

	return LOG4CXX_STR("level");
}
