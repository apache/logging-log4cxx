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
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(LoggerRepository)
		END_LOG4CXX_CAST_MAP()
		virtual ~LoggerRepository();

		/**
		Add \c listener to the repository.
		*/
		virtual void addHierarchyEventListener(const HierarchyEventListenerPtr& listener) = 0;

		/**
		 * Remove \c listener from the repository.
		 *
		 */
		virtual void removeHierarchyEventListener(const spi::HierarchyEventListenerPtr& listener) = 0;

		/**
		 * Call \c configurator if not yet configured and \c configurator has not already been tried.
		 * If \c configurator succeeds, it must call LoggerRepository::setConfigured
		 * to ensure subsequent calls to LoggerRepository::ensureIsConfigured
		 * from overwriting the configuration.
		 */
		virtual void ensureIsConfigured(std::function<void()> configurator) = 0;

		/**
		Is the repository disabled for \c level? The answer depends
		on the repository threshold and the <code>level</code>
		parameter. See also the #setThreshold method.
		*/
		virtual bool isDisabled(int level) const = 0;

		/**
		Enable logging for logging requests with level <code>newLevel</code> or higher.
		All logging requests below the threshold are immediately dropped.
		By default, the threshold is set to <code>Level::getAll()</code> which has the lowest possible rank.
		*/
		virtual void setThreshold(const LevelPtr& newLevel) = 0;

		/**
		Enable logging for logging requests with level <code>newLevel</code> or higher.
		The threshold is set the <code>DEBUG</code> if \c newLevel is not recognised by Level::getLevel.
		All logging requests below the threshold are immediately dropped.
		By default, the threshold is set to <code>Level::getAll()</code> which has the lowest possible rank.
		*/
		virtual void setThreshold(const LogString& newLevel) = 0;

		/**
		Add a warning to internal debug output that \c logger does not have any Appender attached.
		To avoid overloading the output stream, the warning is emitted only once.
		*/
		virtual void emitNoAppenderWarning(const Logger* logger) = 0;

		/**
		The current repository-wide threshold.

		See #setThreshold for an explanation.
		*/
		virtual LevelPtr getThreshold() const = 0;

		/**
		Retrieve the \c name Logger instance.

		If a logger of that name already exists, it will be returned.
		Otherwise, a new logger will be instantiated,
		optionally by calling <code>factory->makeNewLoggerInstance()</code>.

		@param name The logger to retrieve.
		@param factory If provided, used to instantiate a new logger.
		*/
		virtual LoggerPtr getLogger(const LogString& name,
			const spi::LoggerFactoryPtr& factory = {}) = 0;

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

		/**
		The logger that cannot be retrieved by name.
		*/
		virtual LoggerPtr getRootLogger() const = 0;

		/**
		Does \c name exist in the repository?
		@returns The Logger instance if \c name exists in the repository.
		*/
		virtual LoggerPtr exists(const LogString& name) = 0;

		/**
		Close and remove all appenders in all categories including the root logger.
		The configured status becomes <code>false</code>.
		*/
		virtual void shutdown() = 0;

		/**
		All the loggers currently defined in this repository.

		The root logger is <em>not</em> included in the returned
		LoggerList.
		*/
		virtual LoggerList getCurrentLoggers() const = 0;

		/**
		Call addAppenderEvent on all registered listeners.
		*/
		virtual void fireAddAppenderEvent(const Logger* logger,	const Appender* appender);

		/**
		Call removeAppenderEvent on all registered listeners.
		*/
		virtual void fireRemoveAppenderEvent(const Logger* logger, const Appender* appender);

		/**
		Reset all values contained in this repository instance to their default.
		This removes all appenders from all categories, sets
		the level of all non-root categories to <code>null</code>,
		sets their additivity flag to <code>true</code> and sets the level
		of the root logger to DEBUG.
		Also the repository wide threshold is set its default "ALL" value.

		Existing categories are not removed.

		This method should be used sparingly and with care as it will
		block all logging until this is configured again.
		*/
		virtual void resetConfiguration() = 0;

		/**
		The value of the configured status.
		*/
		virtual bool isConfigured() = 0;

		/**
		Set the configured status to <code>true</code>.
		*/
		virtual void setConfigured(bool configured) = 0;

		/**
		Refresh the configuration of all loggers where \c parent
		is somewhere in their ancestor chain.
		The ancestor chain ends at the root logger.
		*/
		virtual void updateChildren(const Logger* parent) = 0;
}; // class LoggerRepository

}  // namespace spi
} // namespace log4cxx

#endif //_LOG4CXX_SPI_LOG_REPOSITORY_H
