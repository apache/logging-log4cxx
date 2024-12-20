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
#define __STDC_CONSTANT_MACROS
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/filewatchdog.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/helpers/stringhelper.h>
#include <functional>
#include <chrono>
#include <thread>
#include <condition_variable>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

long FileWatchdog::DEFAULT_DELAY = 60000;

struct FileWatchdog::FileWatchdogPrivate{
	FileWatchdogPrivate(const File& file1) :
		file(file1), delay(DEFAULT_DELAY), lastModif(0),
		warnedAlready(false)
	{ }


	/**
	The name of the file to observe  for changes.
	*/
	File file;

	/**
	The delay to observe between every check.
	By default set DEFAULT_DELAY.*/
	long delay;
	log4cxx_time_t lastModif;
	bool warnedAlready;
#if LOG4CXX_ABI_VERSION <= 15
	int interrupted{ 0 };
	Pool pool;
	std::thread thread;
	std::condition_variable interrupt;
	std::mutex interrupt_mutex;
#endif
	LogString taskName{LOG4CXX_STR("FileWatchdog")};
};

FileWatchdog::FileWatchdog(const File& file1)
	: m_priv(std::make_unique<FileWatchdogPrivate>(file1))
{
}

FileWatchdog::~FileWatchdog()
{
	stop();
}


bool FileWatchdog::is_active()
{
	return ThreadUtility::instance()->hasPeriodicTask(m_priv->taskName);
}

void FileWatchdog::stop()
{
	if (is_active())
	{
		LogLog::debug(LOG4CXX_STR("Stopping file watchdog"));
		ThreadUtility::instance()->removePeriodicTask(m_priv->taskName);
	}
}

const File& FileWatchdog::file()
{
	return m_priv->file;
}

void FileWatchdog::checkAndConfigure()
{
	if (LogLog::isDebugEnabled())
	{
		LogString msg(LOG4CXX_STR("Checking ["));
		msg += m_priv->file.getPath();
		msg += LOG4CXX_STR("]");
		LogLog::debug(msg);
	}
	Pool pool1;

	if (!m_priv->file.exists(pool1))
	{
		if (!m_priv->warnedAlready)
		{
			LogLog::warn(LOG4CXX_STR("[")
				+ m_priv->file.getPath()
				+ LOG4CXX_STR("] does not exist."));
			m_priv->warnedAlready = true;
		}
	}
	else
	{
		auto thisMod = m_priv->file.lastModified(pool1);

		if (thisMod > m_priv->lastModif)
		{
			m_priv->lastModif = thisMod;
			doOnChange();
			m_priv->warnedAlready = false;
		}
	}
}

void FileWatchdog::start()
{
	checkAndConfigure();
	auto p = ThreadUtility::instance();
	if (!p->hasPeriodicTask(m_priv->taskName))
	{
		if (LogLog::isDebugEnabled())
		{
			Pool p;
			LogString msg(LOG4CXX_STR("Checking ["));
			msg += m_priv->file.getPath();
			msg += LOG4CXX_STR("] at ");
			StringHelper::toString((int)m_priv->delay, p, msg);
			msg += LOG4CXX_STR(" ms interval");
			LogLog::debug(msg);
		}
		p->addPeriodicTask(m_priv->taskName
			, std::bind(&FileWatchdog::checkAndConfigure, this)
			, std::chrono::milliseconds(m_priv->delay)
			);
	}
}

void FileWatchdog::setDelay(long delay1){
	m_priv->delay = delay1;
	auto p = ThreadUtility::instance();
	if (p->hasPeriodicTask(m_priv->taskName))
	{
		p->removePeriodicTask(m_priv->taskName);
		p->addPeriodicTask(m_priv->taskName
			, std::bind(&FileWatchdog::checkAndConfigure, this)
			, std::chrono::milliseconds(m_priv->delay)
			);
	}
}
