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
#include <memory>
#include <functional>
#include <chrono>
#include <thread>
#include <condition_variable>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

long FileWatchdog::DEFAULT_DELAY = 60000;

struct FileWatchdog::FileWatchdogPrivate
{
	FileWatchdogPrivate
		( const File&                     filename
		, const spi::ConfiguratorPtr&     processor
		, const spi::LoggerRepositoryPtr& target
		)
		: file(filename)
		, taskName{ LOG4CXX_STR("WatchDog_") + filename.getName() }
		, pConfigurator(processor)
		, pRepository(target)
	{ }

	File file;
	long millisecondDelay{ DEFAULT_DELAY };
	log4cxx_time_t lastModif{ 0 };
	bool warnedAlready { false };
	LogString taskName;
	ThreadUtility::ManagerWeakPtr taskManager;

	/**
	Serialize access and modification to: file, lastModif and warnedAlready.
	Recursive because doOnChange may re-enter watchdog methods.
	*/
	std::recursive_mutex mutex;

	/// The configuration file processor
	spi::ConfiguratorPtr pConfigurator;

	/// The configuration target
	spi::LoggerRepositoryPtr pRepository;

	/// The result of the most recent spi::Configurator::doConfigure call.
	spi::ConfigurationStatus configResult{ spi::ConfigurationStatus::NotConfigured };

	/// Call checkAndConfigure() on \c parent and then add an asynchronous task that periodically checks for a file change.
	void start(const FileWatchdogPtr& parent);
};

FileWatchdog::FileWatchdog
	( const File&                     filename
	, const spi::ConfiguratorPtr&     processor
	, const spi::LoggerRepositoryPtr& target
	)
	: m_priv{ std::make_shared<FileWatchdogPrivate>(filename, processor, target) }
{
}

FileWatchdog::~FileWatchdog()
{
	stop();
}


bool FileWatchdog::is_active()
{
	bool result = false;
	if (auto p = m_priv->taskManager.lock())
		result = p->value().hasPeriodicTask(m_priv->taskName);
	return result;
}

void FileWatchdog::stop()
{
	if (auto p = m_priv->taskManager.lock())
		p->value().removePeriodicTask(m_priv->taskName);
}

/**
Stop all tasks that periodically checks for a file change.
*/
void FileWatchdog::stopAll()
{
	ThreadUtility::instance()->removePeriodicTasksMatching(LOG4CXX_STR("WatchDog_"));
}

const File& FileWatchdog::file()
{
	return m_priv->file;
}

void FileWatchdog::checkAndConfigure()
{
	std::lock_guard<std::recursive_mutex> lock(m_priv->mutex);
	if (LogLog::isDebugEnabled())
	{
		LogString msg(LOG4CXX_STR("Checking ["));
		msg += m_priv->file.getPath();
		msg += LOG4CXX_STR("]");
		LogLog::debug(msg);
	}

	if (!m_priv->file.exists())
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
		auto thisMod = m_priv->file.lastModified();

		if (thisMod > m_priv->lastModif)
		{
			m_priv->lastModif = thisMod;
			doOnChange();
			m_priv->warnedAlready = false;
		}
	}
}

auto FileWatchdog::getSharedPtr() -> FileWatchdogPtr
{
    // The aliasing constructor returns a pointer to 'this' (FileWatchdog*)
    // but increments/decrements the ref-count of 'm_priv'.
    return std::shared_ptr<FileWatchdog>(m_priv, this);
}

void FileWatchdog::start()
{
	m_priv->start(getSharedPtr());
}

void FileWatchdog::FileWatchdogPrivate::start(const FileWatchdogPtr& parent)
{
	auto taskManager = ThreadUtility::instancePtr();
	parent->checkAndConfigure();
	if (!taskManager->value().hasPeriodicTask(this->taskName))
	{
		if (LogLog::isDebugEnabled())
		{
			LogString msg(LOG4CXX_STR("Checking ["));
			msg += this->file.getPath();
			msg += LOG4CXX_STR("] at ");
			StringHelper::toString((int)this->millisecondDelay, msg);
			msg += LOG4CXX_STR(" ms interval");
			LogLog::debug(msg);
		}
		taskManager->value().addPeriodicTask(this->taskName
			, [parent](){ parent->checkAndConfigure(); }
			, std::chrono::milliseconds(this->millisecondDelay)
			);
		this->taskManager = taskManager;
	}
}

void FileWatchdog::setDelay(long millisecondDelay)
{
	m_priv->millisecondDelay = millisecondDelay;
	auto p = m_priv->taskManager.lock();
	if (p && p->value().hasPeriodicTask(m_priv->taskName))
	{
		p->value().removePeriodicTask(m_priv->taskName);
		auto pThis = getSharedPtr();
		p->value().addPeriodicTask(m_priv->taskName
			, [pThis](){ pThis->checkAndConfigure(); }
			, std::chrono::milliseconds(m_priv->millisecondDelay)
			);
	}
}

void FileWatchdog::setFile(const File& newValue)
{
	std::lock_guard<std::recursive_mutex> lock(m_priv->mutex);
	if (m_priv->file.getPath() != newValue.getPath())
	{
		m_priv->file = newValue;
		m_priv->lastModif = 0;
	}
}

void FileWatchdog::doOnChange()
{
	if (m_priv->pConfigurator)
		m_priv->configResult = m_priv->pConfigurator->doConfigure(m_priv->file, m_priv->pRepository);
	else
		m_priv->configResult = spi::ConfigurationStatus::NotConfigured;
}

auto FileWatchdog::startWatching
	( const File&                     filename
	, const spi::ConfiguratorPtr&     processor
	, const spi::LoggerRepositoryPtr& target
	, long                            millisecondDelay
	) -> spi::ConfigurationStatus
{
	auto pDog = std::shared_ptr<FileWatchdog>(new FileWatchdog(filename, processor, target));
	if (0 < millisecondDelay)
		pDog->setDelay(millisecondDelay);
	pDog->m_priv->start(pDog);
	return pDog->getStatus();
}

auto FileWatchdog::getStatus() -> spi::ConfigurationStatus
{
	return m_priv->configResult;
}
