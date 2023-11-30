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

#ifndef LOG4CXX_LOGGER_INSTANCE_HDR_
#define LOG4CXX_LOGGER_INSTANCE_HDR_

#include <log4cxx/logmanager.h>
#include <log4cxx/logger.h>

namespace LOG4CXX_NS
{

/**
 * A smart pointer (implicity convertable to LoggerPtr)
 * that conditionally removes a Logger from the spi::LoggerRepository
 * at the end of the instance variable's lifetime.

 * If the configuration process loaded settings for the logger,
 * or the logger is referenced elsewhere,
 * the LoggerInstancePtr destructor will not remove it from the spi::LoggerRepository.

 * Use a LoggerInstancePtr to prevent unbounded growth
 * of data in the spi::LoggerRepository
 * when using runtime generated logger names.

 * A runtime generated logger name is a technique for marking logging messages
 * that allows control of the logger level at a class instance level (i.e. a per object logger).

 * A per object logger is useful when the object instance has a identifiable name
 * (e.g. when it is instantiated from configuration data).
 */
 class LoggerInstancePtr
{
	bool m_hadConfiguration; //!< Did the logger repository hold a \c m_logger before creation of this instance?
	LoggerPtr m_logger;
public: // ...structors
	/// A null LoggerPtr
	LoggerInstancePtr() : m_hadConfiguration(false)
	{}
	/// A separately configurable logger named \c instanceName
	template <class StringType>
	LoggerInstancePtr(const StringType& instanceName)
		: m_hadConfiguration(LogManager::exists(instanceName))
		, m_logger(LogManager::getLogger(instanceName))
	{
	}
	/// Conditionally remove the logger from the the spi::LoggerRepository
	~LoggerInstancePtr()
	{
		reset();
	}

	const LoggerPtr& operator->() const noexcept
	{
		return m_logger;
	}

	explicit operator bool() const noexcept
	{
		return !!m_logger;
	}

	operator LoggerPtr&() noexcept
	{
		return m_logger;
	}

	operator const LoggerPtr&() const noexcept
	{
		return m_logger;
	}

	Logger* get() noexcept
	{
		return m_logger.get();
	}

	const Logger* get() const noexcept
	{
		return m_logger.get();
	}

	/// Conditionally remove the Logger from the spi::LoggerRepository
	void reset()
	{
		if (m_logger && !m_hadConfiguration)
		{
			auto name = m_logger->getName();
			m_logger.reset(); // Decrease reference count
			LogManager::removeLogger(name);
		}
		else
		{
			m_hadConfiguration = false;
			m_logger.reset();
		}
	}

	/// Change this to a logger named \c instanceName
	template <class StringType>
	void reset(const StringType& instanceName)
	{
		reset();
		m_hadConfiguration = !!LogManager::exists(instanceName);
		m_logger = LogManager::getLogger(instanceName);
	}
};

} // namespace LOG4CXX_NS

#endif // LOG4CXX_LOGGER_INSTANCE_HDR_
