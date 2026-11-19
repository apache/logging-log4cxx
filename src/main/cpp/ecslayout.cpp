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
#include <log4cxx/ecslayout.h>
#include <log4cxx/jsonlayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/cacheddateformat.h>
#include <log4cxx/helpers/simpledateformat.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/timezone.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/private/layout_priv.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

IMPLEMENT_LOG4CXX_OBJECT(ECSLayout)

namespace
{
// ISO 8601 in UTC with millisecond precision, e.g. 2026-11-15T10:20:30.123Z
const logchar timestampPattern[] = LOG4CXX_STR("yyyy-MM-ddTHH:mm:ss.SSSZ");

// The ECS version the field names conform to
const logchar ecsVersion[] = LOG4CXX_STR("1.2.0");

DateFormatPtr makeTimestampFormat()
{
	auto result = std::make_shared<SimpleDateFormat>(timestampPattern);
	result->setTimeZone(TimeZone::getGMT());
	return result;
}

// Append a separator and the quoted field name followed by ':'
void appendFieldName(LogString& buf, const LogString& name)
{
	buf.push_back(0x2C); // ','
	JSONLayout::appendItem(name, buf);
	buf.push_back(0x3A); // ':'
}

void appendField(LogString& buf, const LogString& name, const LogString& value)
{
	appendFieldName(buf, name);
	JSONLayout::appendItem(value, buf);
}

} // namespace

struct ECSLayout::ECSLayoutPrivate
{
	LogString serviceName;
	LogString serviceVersion;
	LogString serviceEnvironment;
	LogString serviceNodeName;
	LogString eventDataset;

	// Print no location info by default
	bool locationInfo{ false };

	pattern::CachedDateFormat dateFormat
		{ makeTimestampFormat()
		, pattern::CachedDateFormat::getMaximumCacheValidity(timestampPattern)
		};

	// Expected length of a formatted event excluding the message text
	size_t expectedPatternLength{ 100 };

	const LogString& getEventDataset() const
	{
		return eventDataset.empty() ? serviceName : eventDataset;
	}

	// Is \c name the name of a field already added to the output?
	bool isOutputField(const LogString& name, bool hasTags, bool hasOrigin) const
	{
		return name == LOG4CXX_STR("@timestamp")
			|| name == LOG4CXX_STR("log.level")
			|| name == LOG4CXX_STR("message")
			|| name == LOG4CXX_STR("ecs.version")
			|| name == LOG4CXX_STR("log.logger")
			|| name == LOG4CXX_STR("process.thread.name")
			|| (!serviceName.empty() && name == LOG4CXX_STR("service.name"))
			|| (!serviceVersion.empty() && name == LOG4CXX_STR("service.version"))
			|| (!serviceEnvironment.empty() && name == LOG4CXX_STR("service.environment"))
			|| (!serviceNodeName.empty() && name == LOG4CXX_STR("service.node.name"))
			|| (!getEventDataset().empty() && name == LOG4CXX_STR("event.dataset"))
			|| (hasTags && name == LOG4CXX_STR("tags"))
			|| (hasOrigin &&
				( name == LOG4CXX_STR("log.origin.file.name")
				|| name == LOG4CXX_STR("log.origin.file.line")
				|| name == LOG4CXX_STR("log.origin.function")
				));
	}
};

ECSLayout::ECSLayout() :
	m_priv(std::make_unique<ECSLayoutPrivate>())
{
}

ECSLayout::~ECSLayout() {}

void ECSLayout::setServiceName(const LogString& newValue)
{
	m_priv->serviceName = newValue;
}

const LogString& ECSLayout::getServiceName() const
{
	return m_priv->serviceName;
}

void ECSLayout::setServiceVersion(const LogString& newValue)
{
	m_priv->serviceVersion = newValue;
}

const LogString& ECSLayout::getServiceVersion() const
{
	return m_priv->serviceVersion;
}

void ECSLayout::setServiceEnvironment(const LogString& newValue)
{
	m_priv->serviceEnvironment = newValue;
}

const LogString& ECSLayout::getServiceEnvironment() const
{
	return m_priv->serviceEnvironment;
}

void ECSLayout::setServiceNodeName(const LogString& newValue)
{
	m_priv->serviceNodeName = newValue;
}

const LogString& ECSLayout::getServiceNodeName() const
{
	return m_priv->serviceNodeName;
}

void ECSLayout::setEventDataset(const LogString& newValue)
{
	m_priv->eventDataset = newValue;
}

const LogString& ECSLayout::getEventDataset() const
{
	return m_priv->getEventDataset();
}

void ECSLayout::setLocationInfo(bool newValue)
{
	m_priv->locationInfo = newValue;
}

bool ECSLayout::getLocationInfo() const
{
	return m_priv->locationInfo;
}

LogString ECSLayout::getContentType() const
{
	return LOG4CXX_STR("application/json");
}

bool ECSLayout::activateOptions()
{
	m_priv->expectedPatternLength = priv::doubledLayoutSize(getFormattedEventCharacterCount());
	return true;
}

void ECSLayout::setOption(const LogString& option, const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("SERVICENAME"), LOG4CXX_STR("servicename")))
	{
		setServiceName(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("SERVICEVERSION"), LOG4CXX_STR("serviceversion")))
	{
		setServiceVersion(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("SERVICEENVIRONMENT"), LOG4CXX_STR("serviceenvironment")))
	{
		setServiceEnvironment(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("SERVICENODENAME"), LOG4CXX_STR("servicenodename")))
	{
		setServiceNodeName(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("EVENTDATASET"), LOG4CXX_STR("eventdataset")))
	{
		setEventDataset(value);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("locationinfo")))
	{
		setLocationInfo(OptionConverter::toBoolean(value, false));
	}
	else
		Layout::setOption(option, value);
}

void ECSLayout::format(LogString& output, const spi::LoggingEventPtr& event) const
{
	auto& lsMsg = event->getRenderedMessage();
	priv::reserveFormattedEvent(output, m_priv->expectedPatternLength, lsMsg.size());
	// The ECS logging specification requires these three fields to be first
	output.append(LOG4CXX_STR("{\"@timestamp\":\""));
	m_priv->dateFormat.format(output, event->getTimeStamp());
	output.push_back(0x22); // '"'

	LogString level;
	event->getLevel()->toString(level);
	appendField(output, LOG4CXX_STR("log.level"), level);
	appendField(output, LOG4CXX_STR("message"), lsMsg);

	appendField(output, LOG4CXX_STR("ecs.version"), ecsVersion);
	appendField(output, LOG4CXX_STR("log.logger"), event->getLoggerName());
	appendField(output, LOG4CXX_STR("process.thread.name"), event->getThreadUserName());

	if (!m_priv->serviceName.empty())
		appendField(output, LOG4CXX_STR("service.name"), m_priv->serviceName);
	if (!m_priv->serviceVersion.empty())
		appendField(output, LOG4CXX_STR("service.version"), m_priv->serviceVersion);
	if (!m_priv->serviceEnvironment.empty())
		appendField(output, LOG4CXX_STR("service.environment"), m_priv->serviceEnvironment);
	if (!m_priv->serviceNodeName.empty())
		appendField(output, LOG4CXX_STR("service.node.name"), m_priv->serviceNodeName);
	auto& eventDataset = m_priv->getEventDataset();
	if (!eventDataset.empty())
		appendField(output, LOG4CXX_STR("event.dataset"), eventDataset);

	LogString ndcVal;
	bool hasTags = event->getNDC(ndcVal);
	if (hasTags)
	{
		appendFieldName(output, LOG4CXX_STR("tags"));
		output.push_back(0x5B); // '['
		JSONLayout::appendItem(ndcVal, output);
		output.push_back(0x5D); // ']'
	}

	auto& locInfo = event->getLocationInformation();
	bool hasOrigin = m_priv->locationInfo && 0 <= locInfo.getLineNumber();
	for (auto const& key : event->getMDCKeySet())
	{
		if (m_priv->isOutputField(key, hasTags, hasOrigin))
			continue;
		LogString value;
		event->getMDC(key, value);
		appendField(output, key, value);
	}

	if (hasOrigin)
	{
		LOG4CXX_DECODE_CHAR(fileName, locInfo.getShortFileName());
		appendField(output, LOG4CXX_STR("log.origin.file.name"), fileName);
		appendFieldName(output, LOG4CXX_STR("log.origin.file.line"));
		StringHelper::toString(locInfo.getLineNumber(), output);
		auto functionName = locInfo.getClassName();
		if (!functionName.empty())
			functionName.append("::");
		functionName.append(locInfo.getMethodName());
		LOG4CXX_DECODE_CHAR(lsFunctionName, functionName);
		appendField(output, LOG4CXX_STR("log.origin.function"), lsFunctionName);
	}

	output.push_back(0x7D); // '}'
	output.append(LOG4CXX_EOL);
}
