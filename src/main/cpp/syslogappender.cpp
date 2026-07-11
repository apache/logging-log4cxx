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

#include <log4cxx/net/syslogappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/datagramsocket.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/optionconverter.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/syslogappender_priv.h>
#include <algorithm>

#define LOG_UNDEF -1

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::net;

namespace
{
	constexpr size_t SYSLOG_PACKET_SUFFIX_RESERVED_CHARS = 12;

	void appendPacketSuffix(LogString& item, size_t current, size_t total)
	{
		item.append(LOG4CXX_STR("("));
		StringHelper::toString(current, item);
		item.append(LOG4CXX_STR("/"));
		StringHelper::toString(total, item);
		item.append(LOG4CXX_STR(")"));
	}
}

namespace LOG4CXX_NS
{
namespace net
{
namespace detail
{
LOG4CXX_EXPORT std::vector<LogString> splitSyslogPackets(const LogString& msg, size_t maxMessageLength)
{
	std::vector<LogString> packets;
	auto digitCount = [](size_t value) {
		size_t digits = 1u;
		while (value >= 10u)
		{
			value /= 10u;
			++digits;
		}
		return digits;
	};
	auto reservePackets = [&](size_t count) -> bool
	{
		if (count > packets.max_size())
		{
			LogLog::error(LOG4CXX_STR("SyslogAppender cannot reserve memory for packet splitting; message too large."));
			return false;
		}

		try
		{
			packets.reserve(count);
			return true;
		}
		catch (const std::length_error&)
		{
			LogLog::error(LOG4CXX_STR("SyslogAppender cannot reserve memory for packet splitting; message too large."));
			return false;
		}
	};
	auto splitByChunkSize = [&](size_t chunkSize, bool appendSuffix) -> bool
	{
		const size_t nChunks = msg.size() / chunkSize + ((msg.size() % chunkSize) != 0u ? 1u : 0u);
		if (!reservePackets(nChunks))
		{
			return false;
		}

		for (size_t start = 0u; start < msg.size();)
		{
			const size_t remaining = msg.size() - start;
			const size_t count = std::min(chunkSize, remaining);
			packets.push_back(msg.substr(start, count));
			start += count;
		}

		if (appendSuffix)
		{
			size_t current = 1u;
			for (auto& item : packets)
			{
				appendPacketSuffix(item, current, packets.size());
				++current;
			}
		}

		return true;
	};

	if (maxMessageLength == 0u)
	{
		return packets;
	}

	if (msg.size() <= maxMessageLength)
	{
		packets.push_back(msg);
		return packets;
	}

	size_t chunkSize = maxMessageLength > SYSLOG_PACKET_SUFFIX_RESERVED_CHARS
		? maxMessageLength - SYSLOG_PACKET_SUFFIX_RESERVED_CHARS
		: 1u;

	const size_t maxIterations = 10u;
	for (size_t iter = 0u; iter < maxIterations; ++iter)
	{
		const size_t nChunks = msg.size() / chunkSize + ((msg.size() % chunkSize) != 0u ? 1u : 0u);
		const size_t suffixLen = 2u * digitCount(nChunks) + 3u;

		if (suffixLen <= SYSLOG_PACKET_SUFFIX_RESERVED_CHARS)
		{
			splitByChunkSize(chunkSize, true);
			return packets;
		}

		if (suffixLen >= maxMessageLength)
		{
			LogLog::warn(LOG4CXX_STR("SyslogAppender: suffix does not fit in MaxMessageLength; omitting packet suffix."));
			splitByChunkSize(maxMessageLength, false);
			return packets;
		}

		size_t newChunkSize = maxMessageLength - suffixLen;
		if (newChunkSize == 0u)
		{
			newChunkSize = 1u;
		}

		if (newChunkSize >= chunkSize)
		{
			splitByChunkSize(chunkSize, true);
			return packets;
		}

		chunkSize = newChunkSize;
	}

	splitByChunkSize(chunkSize, true);
	return packets;
}
}
}
}

IMPLEMENT_LOG4CXX_OBJECT(SyslogAppender)

#define _priv static_cast<SyslogAppenderPriv*>(m_priv.get())

SyslogAppender::SyslogAppender()
	: AppenderSkeleton (std::make_unique<SyslogAppenderPriv>())
{
	this->initSyslogFacilityStr();

}

SyslogAppender::SyslogAppender(const LayoutPtr& layout1,
	int syslogFacility1)
	: AppenderSkeleton (std::make_unique<SyslogAppenderPriv>(layout1, syslogFacility1))
{
	this->initSyslogFacilityStr();
}

SyslogAppender::SyslogAppender(const LayoutPtr& layout1,
	const LogString& syslogHost1, int syslogFacility1)
	: AppenderSkeleton (std::make_unique<SyslogAppenderPriv>(layout1, syslogHost1, syslogFacility1))
{
	this->initSyslogFacilityStr();
	setSyslogHost(syslogHost1);
}

SyslogAppender::~SyslogAppender()
{
	_priv->setClosed();
}

/** Release any resources held by this SyslogAppender.*/
void SyslogAppender::close()
{
	_priv->setClosed();

	if (_priv->sw)
	{
		_priv->sw = nullptr;
	}
}

void SyslogAppender::initSyslogFacilityStr()
{
	_priv->facilityStr = getFacilityString(_priv->syslogFacility);

	if (_priv->facilityStr.empty())
	{
		LogString msg(LOG4CXX_STR("\""));
		StringHelper::toString(_priv->syslogFacility, msg);
		msg.append(LOG4CXX_STR("\" is an unknown syslog facility. Defaulting to \"USER\"."));
		LogLog::warn(msg);
		_priv->syslogFacility = LOG_USER;
		_priv->facilityStr = LOG4CXX_STR("user:");
	}
	else
	{
		_priv->facilityStr += LOG4CXX_STR(":");
	}
}

/**
Returns the specified syslog facility as a lower-case String,
e.g. "kern", "user", etc.
*/
LogString SyslogAppender::getFacilityString(
	int syslogFacility)
{
	switch (syslogFacility)
	{
		case LOG_KERN:
			return LOG4CXX_STR("kern");

		case LOG_USER:
			return LOG4CXX_STR("user");

		case LOG_MAIL:
			return LOG4CXX_STR("mail");

		case LOG_DAEMON:
			return LOG4CXX_STR("daemon");

		case LOG_AUTH:
			return LOG4CXX_STR("auth");

		case LOG_SYSLOG:
			return LOG4CXX_STR("syslog");

		case LOG_LPR:
			return LOG4CXX_STR("lpr");

		case LOG_NEWS:
			return LOG4CXX_STR("news");

		case LOG_UUCP:
			return LOG4CXX_STR("uucp");

		case LOG_CRON:
			return LOG4CXX_STR("cron");
#ifdef LOG_AUTHPRIV

		case LOG_AUTHPRIV:
			return LOG4CXX_STR("authpriv");
#endif
#ifdef LOG_FTP

		case LOG_FTP:
			return LOG4CXX_STR("ftp");
#endif

		case LOG_LOCAL0:
			return LOG4CXX_STR("local0");

		case LOG_LOCAL1:
			return LOG4CXX_STR("local1");

		case LOG_LOCAL2:
			return LOG4CXX_STR("local2");

		case LOG_LOCAL3:
			return LOG4CXX_STR("local3");

		case LOG_LOCAL4:
			return LOG4CXX_STR("local4");

		case LOG_LOCAL5:
			return LOG4CXX_STR("local5");

		case LOG_LOCAL6:
			return LOG4CXX_STR("local6");

		case LOG_LOCAL7:
			return LOG4CXX_STR("local7");

		default:
			return LogString();
	}
}

int SyslogAppender::getFacility(
	const LogString& s)
{
	if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("KERN"), LOG4CXX_STR("kern")))
	{
		return LOG_KERN;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("USER"), LOG4CXX_STR("user")))
	{
		return LOG_USER;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("MAIL"), LOG4CXX_STR("mail")))
	{
		return LOG_MAIL;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("DAEMON"), LOG4CXX_STR("daemon")))
	{
		return LOG_DAEMON;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("AUTH"), LOG4CXX_STR("auth")))
	{
		return LOG_AUTH;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("SYSLOG"), LOG4CXX_STR("syslog")))
	{
		return LOG_SYSLOG;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LPR"), LOG4CXX_STR("lpr")))
	{
		return LOG_LPR;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("NEWS"), LOG4CXX_STR("news")))
	{
		return LOG_NEWS;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("UUCP"), LOG4CXX_STR("uucp")))
	{
		return LOG_UUCP;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("CRON"), LOG4CXX_STR("cron")))
	{
		return LOG_CRON;
	}

#ifdef LOG_AUTHPRIV
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("AUTHPRIV"), LOG4CXX_STR("authpriv")))
	{
		return LOG_AUTHPRIV;
	}

#endif
#ifdef LOG_FTP
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("FTP"), LOG4CXX_STR("ftp")))
	{
		return LOG_FTP;
	}

#endif
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL0"), LOG4CXX_STR("local0")))
	{
		return LOG_LOCAL0;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL1"), LOG4CXX_STR("local1")))
	{
		return LOG_LOCAL1;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL2"), LOG4CXX_STR("local2")))
	{
		return LOG_LOCAL2;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL3"), LOG4CXX_STR("local3")))
	{
		return LOG_LOCAL3;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL4"), LOG4CXX_STR("local4")))
	{
		return LOG_LOCAL4;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL5"), LOG4CXX_STR("local5")))
	{
		return LOG_LOCAL5;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL6"), LOG4CXX_STR("local6")))
	{
		return LOG_LOCAL6;
	}
	else if (StringHelper::equalsIgnoreCase(s, LOG4CXX_STR("LOCAL7"), LOG4CXX_STR("local7")))
	{
		return LOG_LOCAL7;
	}
	else
	{
		return LOG_UNDEF;
	}
}

void SyslogAppender::append( LOG4CXX_APPEND_FORMAL_PARAMETERS )
{
	if  (!isAsSevereAsThreshold(event->getLevel()))
	{
		return;
	}

	LogString msg;
	std::string encoded;
	_priv->layout->format(msg, event);

	Transcoder::encode(msg, encoded);
	auto packets = detail::splitSyslogPackets(msg, static_cast<size_t>(_priv->maxMessageLength));
	if (packets.empty() && !msg.empty())
	{
		return;
	}

	// On the local host, we can directly use the system function 'syslog'
	// if it is available
#if LOG4CXX_HAVE_SYSLOG

	if (_priv->sw == 0)
	{
		for (auto const& item : packets)
		{
			// use of "%s" to avoid a security hole
			LOG4CXX_ENCODE_CHAR(itemStr, item);
			::syslog(_priv->syslogFacility | event->getLevel()->getSyslogEquivalent(),
				"%s", itemStr.c_str());
		}

		return;
	}

#endif

	// We must not attempt to append if sw is null.
	if (_priv->sw == 0)
	{
		_priv->errorHandler->error(LOG4CXX_STR("No syslog host is set for SyslogAppedender named \"") +
			_priv->name + LOG4CXX_STR("\"."));
		return;
	}

	for (auto const& item : packets)
	{
		LogString sbuf(1, 0x3C /* '<' */);
		StringHelper::toString((_priv->syslogFacility | event->getLevel()->getSyslogEquivalent()), sbuf);
		sbuf.append(1, (logchar) 0x3E /* '>' */);

		if (_priv->facilityPrinting)
		{
			sbuf.append(_priv->facilityStr);
		}

		sbuf.append(item);
		_priv->sw->write(sbuf);
	}
}

#if LOG4CXX_ABI_VERSION <= 15
void SyslogAppender::activateOptions(Pool&)
{
}
#endif

void SyslogAppender::setOption(const LogString& option, const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("SYSLOGHOST"), LOG4CXX_STR("sysloghost")))
	{
		setSyslogHost(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("FACILITY"), LOG4CXX_STR("facility")))
	{
		setFacility(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("MAXMESSAGELENGTH"), LOG4CXX_STR("maxmessagelength")))
	{
		setMaxMessageLength(OptionConverter::toInt(value, 1024));
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}

void SyslogAppender::setSyslogHost(const LogString& syslogHost1)
{
	if (_priv->sw != 0)
	{
		_priv->sw = nullptr;
	}

	LogString slHost = syslogHost1;
	int slHostPort = -1;

	LogString::size_type colonPos = 0;
	colonPos = slHost.rfind(':');

	if (colonPos != LogString::npos)
	{
		slHostPort = StringHelper::toInt(slHost.substr(colonPos + 1));
		// Erase the :port part of the host name
		slHost.erase( colonPos );
	}

	// On the local host, we can directly use the system function 'syslog'
	// if it is available (cf. append)
#if LOG4CXX_HAVE_SYSLOG

	if (syslogHost1 != LOG4CXX_STR("localhost") && syslogHost1 != LOG4CXX_STR("127.0.0.1")
		&& !syslogHost1.empty())
#endif
	{
		if (slHostPort >= 0)
		{
			_priv->sw = std::make_unique<SyslogWriter>(slHost, slHostPort);
		}
		else
		{
			_priv->sw = std::make_unique<SyslogWriter>(slHost);
		}
	}

	_priv->syslogHost = slHost;
	_priv->syslogHostPort = slHostPort;
}


void SyslogAppender::setFacility(const LogString& facilityName)
{
	if (facilityName.empty())
	{
		return;
	}

	_priv->syslogFacility = getFacility(facilityName);

	if (_priv->syslogFacility == LOG_UNDEF)
	{
		LogLog::warn(LOG4CXX_STR("[") + facilityName +
			LOG4CXX_STR("] is an unknown syslog facility. Defaulting to [USER]."));
		_priv->syslogFacility = LOG_USER;
	}

	this->initSyslogFacilityStr();
}

const LogString& SyslogAppender::getSyslogHost() const
{
	return _priv->syslogHost;
}

LogString SyslogAppender::getFacility() const
{
	return getFacilityString(_priv->syslogFacility);
}

void SyslogAppender::setFacilityPrinting(bool facilityPrinting1)
{
	_priv->facilityPrinting = facilityPrinting1;
}

bool SyslogAppender::getFacilityPrinting() const
{
	return _priv->facilityPrinting;
}

void SyslogAppender::setMaxMessageLength(int maxMessageLength1)
{
	// append() reserves 12 characters per chunk for an "(x/y)" sequence suffix.
	// A value at or below the suffix size produces a zero-length chunk (causing
	// an infinite split loop) or an iterator computed before msg.begin() (UB).
	static const int MIN_MAX_MESSAGE_LENGTH = 13;
	if (maxMessageLength1 < MIN_MAX_MESSAGE_LENGTH)
	{
		LogLog::warn(LOG4CXX_STR("SyslogAppender MaxMessageLength is too small. Using the default value."));
		maxMessageLength1 = 1024;
	}
	_priv->maxMessageLength = maxMessageLength1;
}

int SyslogAppender::getMaxMessageLength() const
{
	return _priv->maxMessageLength;
}
