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
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>
#include <iostream>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>
#include <log4cxx/helpers/aprinitializer.h>
#include <log4cxx/helpers/systemerrwriter.h>
#include <log4cxx/helpers/optionconverter.h>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

struct LogLog::LogLogPrivate {
	LogLogPrivate() :
		debugEnabled(false),
		quietMode(false){}

	~LogLogPrivate()
	{
		quietMode = true; // Prevent output after deletion by onexit processing chain.
	}

	bool debugEnabled;

	/**
		   In quietMode not even errors generate any output.
	 */
	bool quietMode;
	std::mutex mutex;
	LogString errorPrefix;
	LogString warnPrefix;
	LogString debugPrefix;
	LogString suffix;
	void setColorEnabled(bool newValue)
	{
		if (newValue)
		{
			this->errorPrefix = LOG4CXX_STR("\x1B[31m"); //red
			this->warnPrefix = LOG4CXX_STR("\x1B[33m"); //yellow
			this->debugPrefix = LOG4CXX_STR("\x1B[32m"); //green
			this->suffix = LOG4CXX_STR("\x1B[0m"); // none
		}
		else
		{
			this->errorPrefix.clear();
			this->warnPrefix.clear();
			this->debugPrefix.clear();
			this->suffix.clear();
		}
	}
};

LogLog::LogLog() :
	m_priv(std::make_unique<LogLogPrivate>())
{
	LogString log4cxxDebug = OptionConverter::getSystemProperty(LOG4CXX_STR("LOG4CXX_DEBUG"), LOG4CXX_STR("false"));
	m_priv->debugEnabled = OptionConverter::toBoolean(log4cxxDebug, false);
	auto color = OptionConverter::getSystemProperty(LOG4CXX_STR("LOG4CXX_COLOR"), LOG4CXX_STR("true"));
	m_priv->setColorEnabled(OptionConverter::toBoolean(color, true));
}

LogLog::~LogLog()
{ m_priv.reset(); }

LogLog& LogLog::getInstance()
{
	static WideLife<LogLog> internalLogger;

	return internalLogger;
}

bool LogLog::isDebugEnabled()
{
	auto p = getInstance().m_priv.get();
	return p && !p->quietMode // Not deleted by onexit processing?
			 && p->debugEnabled;
}

void LogLog::setInternalDebugging(bool debugEnabled1)
{
	auto p = getInstance().m_priv.get();
	if (p && !p->quietMode) // Not deleted by onexit processing?
		p->debugEnabled = debugEnabled1;
}

bool LogLog::isColorEnabled()
{
	auto p = getInstance().m_priv.get();
	return p && !p->errorPrefix.empty();
}

void LogLog::setColorEnabled(bool newValue)
{
	if (auto p = getInstance().m_priv.get())
		p->setColorEnabled(newValue);
}

void LogLog::debug(const LogString& msg)
{
	auto p = getInstance().m_priv.get();
	if (p && !p->quietMode) // Not deleted by onexit processing?
	{
		if (!p->debugEnabled)
		{
			return;
		}

		std::lock_guard<std::mutex> lock(p->mutex);

		emit_log(p->debugPrefix, msg, p->suffix);
	}
}

void LogLog::debug(const LogString& msg, const std::exception& e)
{
	auto p = getInstance().m_priv.get();
	if (p && !p->quietMode) // Not deleted by onexit processing?
	{
		if (!p->debugEnabled)
			return;

		std::lock_guard<std::mutex> lock(p->mutex);
		emit_log(p->debugPrefix, msg, p->suffix);
		emit_log(p->debugPrefix, e, p->suffix);
	}
}


void LogLog::error(const LogString& msg)
{
	auto p = getInstance().m_priv.get();
	if (p && !p->quietMode) // Not deleted by onexit processing?
	{
		std::lock_guard<std::mutex> lock(p->mutex);

		emit_log(p->errorPrefix, msg, p->suffix);
	}
}

void LogLog::error(const LogString& msg, const std::exception& e)
{
	auto p = getInstance().m_priv.get();
	if (p && !p->quietMode) // Not deleted by onexit processing?
	{
		std::lock_guard<std::mutex> lock(p->mutex);
		emit_log(p->errorPrefix, msg, p->suffix);
		emit_log(p->errorPrefix, e, p->suffix);
	}
}

void LogLog::setQuietMode(bool quietMode1)
{
	auto p = getInstance().m_priv.get();
	std::lock_guard<std::mutex> lock(p->mutex);

	p->quietMode = quietMode1;
}

void LogLog::warn(const LogString& msg)
{
	auto p = getInstance().m_priv.get();
	if (p && !p->quietMode) // Not deleted by onexit processing?
	{
		std::lock_guard<std::mutex> lock(p->mutex);
		emit_log(p->warnPrefix, msg, p->suffix);
	}
}

void LogLog::warn(const LogString& msg, const std::exception& e)
{
	auto p = getInstance().m_priv.get();
	if (p && !p->quietMode) // Not deleted by onexit processing?
	{
		std::lock_guard<std::mutex> lock(p->mutex);
		emit_log(p->warnPrefix, msg, p->suffix);
		emit_log(p->warnPrefix, e, p->suffix);
	}
}

void LogLog::emit_log(const LogString& prefix, const LogString& msg, const LogString& suffix)
{
	LogString out(LOG4CXX_STR("log4cxx: "));
	out.append(prefix);
	out.append(msg);
	out.append(suffix);
	out.append(1, (logchar) 0x0A);

	SystemErrWriter::write(out);
}

void LogLog::emit_log(const LogString& prefix, const std::exception& ex, const LogString& suffix)
{
	LogString out(LOG4CXX_STR("log4cxx: "));
	out.append(prefix);
	const char* raw = ex.what();

	if (raw != 0)
	{
		Transcoder::decode(raw, out);
	}
	else
	{
		out.append(LOG4CXX_STR("std::exception::what() == null"));
	}

	out.append(suffix);
	out.append(1, (logchar) 0x0A);

	SystemErrWriter::write(out);
}
