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
 * Conditionally removes a Logger at the end of the instance variable's lifetime.
 */
 class LoggerInstancePtr
{
	bool m_hadConfiguration; //!< Did the logger repository hold the m_logger before creation of this instance?
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
	/// Remove the logger from the single global map
	~LoggerInstancePtr()
	{
		if (m_logger && !m_hadConfiguration)
		{
			auto name = m_logger->getName();
			m_logger.reset(); // Decrease reference count
			LogManager::removeLogger(name);
		}
	}
	const LoggerPtr& operator->() const noexcept
	{
        return m_logger;
    }

	operator LoggerPtr&() noexcept
	{
		return m_logger;
	}

	operator const LoggerPtr&() const noexcept
	{
		return m_logger;
	}

	LoggerPtr& value() noexcept
	{
		return m_logger;
	}

	const LoggerPtr& value() const noexcept
	{
		return m_logger;
	}
private: // Prevent copies and assignment
	LoggerInstancePtr(const LoggerInstancePtr&) = delete;
	LoggerInstancePtr(LoggerInstancePtr&&) = delete;
	LoggerInstancePtr& operator=(const LoggerInstancePtr&) = delete;
	LoggerInstancePtr& operator=(LoggerInstancePtr&&) = delete;
};

} // namespace LOG4CXX_NS

#endif // LOG4CXX_LOGGER_INSTANCE_HDR_
