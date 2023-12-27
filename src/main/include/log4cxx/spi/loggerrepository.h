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

#ifndef _LOG4CXX_SPI_LOG_REPOSITORY_H
#define _LOG4CXX_SPI_LOG_REPOSITORY_H

#include <log4cxx/appender.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/level.h>
#include <log4cxx/spi/hierarchyeventlistener.h>
#include <functional>

namespace LOG4CXX_NS
{
namespace spi
{

/**
A <code>LoggerRepository</code> is used to create and retrieve
<code>Loggers</code>. The relation between loggers in a repository
depends on the repository but typically loggers are arranged in a
named hierarchy.

<p>In addition to the creational methods, a
<code>LoggerRepository</code> can be queried for existing loggers,
can act as a point of registry for events related to loggers.
*/
class LOG4CXX_EXPORT LoggerRepository : public virtual helpers::Object
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(LoggerRepository)
		virtual ~LoggerRepository() {}

		/**
		Add a {@link spi::HierarchyEventListener HierarchyEventListener}
		        event to the repository.
		*/
		virtual void addHierarchyEventListener(const HierarchyEventListenerPtr&
			listener) = 0;

#if 15 < LOG4CXX_ABI_VERSION
		/**
		 * Remove a previously added HierarchyEventListener from the repository.
		 *
		 */
		virtual void removeHierarchyEventListener(const spi::HierarchyEventListenerPtr& listener) = 0;
#endif

		/**
		 * Call \c configurator if not yet configured.
		 */
		virtual void ensureIsConfigured(std::function<void()> configurator) = 0;

		/**
		Is the repository disabled for a given level? The answer depends
		on the repository threshold and the <code>level</code>
		parameter. See also #setThreshold method.  */
		virtual bool isDisabled(int level) const = 0;

		/**
		Set the repository-wide threshold. All logging requests below the
		threshold are immediately dropped. By default, the threshold is
		set to <code>Level::getAll()</code> which has the lowest possible rank.  */
		virtual void setThreshold(const LevelPtr& level) = 0;

		/**
		Another form of {@link #setThreshold(const LevelPtr&)
		            setThreshold} accepting a string
		parameter instead of a <code>Level</code>. */
		virtual void setThreshold(const LogString& val) = 0;

		virtual void emitNoAppenderWarning(const Logger* logger) = 0;

		/**
		Get the repository-wide threshold.

		See setThreshold for an explanation.
		*/
		virtual LevelPtr getThreshold() const = 0;

		/**
		Retrieve the \c name Logger instance
		*/
		virtual LoggerPtr getLogger(const LogString& name) = 0;

		/**
		Retrieve the \c name Logger instance

		If a logger of that name already exists, then it will be
		returned.  Otherwise, a new logger will be instantiated by the
		provided <code>factory</code>.

		@param name The name of the logger to retrieve.
		@param factory The factory that will make the new logger instance.
		*/
		virtual LoggerPtr getLogger(const LogString& name,
			const spi::LoggerFactoryPtr& factory) = 0;

#if 15 < LOG4CXX_ABI_VERSION
		/**
		Remove the \c name Logger from the repository.

		Note: The \c name Logger must be retrieved from the repository
		\b after any subsequent configuration file change
		for the newly loaded settings to be used.

		@param name The logger to remove.
		@param ifNotUsed If true and use_count() indicates there are other references, do not remove the Logger and return false.
		@returns true if \c name Logger was removed from the repository.
		*/
		virtual bool removeLogger(const LogString& name, bool ifNotUsed = true) = 0;
#endif

		virtual LoggerPtr getRootLogger() const = 0;

		virtual LoggerPtr exists(const LogString& name) = 0;

		virtual void shutdown() = 0;

		virtual LoggerList getCurrentLoggers() const = 0;

		virtual void fireAddAppenderEvent(const Logger* logger,	const Appender* appender) {};

		virtual void fireRemoveAppenderEvent(const Logger* logger, const Appender* appender) {};

		virtual void resetConfiguration() = 0;

		virtual bool isConfigured() = 0;
		virtual void setConfigured(bool configured) = 0;
}; // class LoggerRepository

}  // namespace spi
} // namespace log4cxx

#endif //_LOG4CXX_SPI_LOG_REPOSITORY_H
