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

#ifndef _LOG4CXX_LOGGER_H
#define _LOG4CXX_LOGGER_H

#include <log4cxx/spi/appenderattachable.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/helpers/resourcebundle.h>
#include <log4cxx/helpers/messagebuffer.h>

namespace LOG4CXX_NS
{

namespace spi
{
class LoggerRepository;
LOG4CXX_PTR_DEF(LoggerRepository);
class LoggerFactory;
LOG4CXX_PTR_DEF(LoggerFactory);
}

class Logger;
/** smart pointer to a Logger class */
LOG4CXX_PTR_DEF(Logger);
LOG4CXX_LIST_DEF(LoggerList, LoggerPtr);


/**
This is the central class in the log4cxx package. Most logging
operations, except configuration, are done through this class.
*/
class LOG4CXX_EXPORT Logger
	: public virtual spi::AppenderAttachable
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Logger)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Logger)
		LOG4CXX_CAST_ENTRY(spi::AppenderAttachable)
		END_LOG4CXX_CAST_MAP()

	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(LoggerPrivate, m_priv)
		int m_threshold; //!< The cached level of this logger

	public:
		/**
		This constructor initializes a new <code>logger</code> instance and
		sets its name.

		<p>It is intended to be only used by factory-classes.
		*/
		Logger(const LogString& name);
#if LOG4CXX_ABI_VERSION <= 15
		[[ deprecated( "Pool is no longer required" ) ]]
		Logger(helpers::Pool& pool, const LogString& name);
#endif
		~Logger();


		/**
		Add <code>newAppender</code> to the list of appenders of this
		Logger instance.

		<p>If <code>newAppender</code> is already in the list of
		appenders, then it won't be added again.
		*/
		void addAppender(const AppenderPtr newAppender) override;


		/**
		Call the appenders in the hierrachy starting at
		<code>this</code>.  If no appenders could be found, emit a
		warning.

		<p>This method calls all the appenders inherited from the
		hierarchy circumventing any evaluation of whether to log or not
		to log the particular log request.

		@param event the event to log.
		@param p memory pool for any allocations needed to process request.
		*/
		void callAppenders(const spi::LoggingEventPtr& event, helpers::Pool& p) const;

		/**
		Close all attached appenders implementing the AppenderAttachable
		interface.
		*/
		void closeNestedAppenders();

		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.
		*/
		void debug(const std::string& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_DEBUG.
		*/
		void debug(const std::string& msg) const;
#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_DEBUG.
		*/
		void debug(const std::wstring& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_DEBUG.
		*/
		void debug(const std::wstring& msg) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_DEBUG.
		*/
		void debug(const std::basic_string<UniChar>& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_DEBUG.
		*/
		void debug(const std::basic_string<UniChar>& msg) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_DEBUG.
		*/
		void debug(const CFStringRef& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>DEBUG</code> events.

		<p>This method first checks if this logger is <code>DEBUG</code>
		enabled by comparing the level of this logger with the
		DEBUG level. If this logger is
		<code>DEBUG</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_DEBUG.
		*/
		void debug(const CFStringRef& msg) const;
#endif

		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_ERROR.
		*/
		void error(const std::string& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_ERROR.
		*/
		void error(const std::string& msg) const;
#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_ERROR.
		*/
		void error(const std::wstring& msg) const;
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_ERROR.
		*/
		void error(const std::wstring& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_ERROR.
		*/
		void error(const std::basic_string<UniChar>& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_ERROR.
		*/
		void error(const std::basic_string<UniChar>& msg) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_ERROR.
		*/
		void error(const CFStringRef& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>ERROR</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_ERROR.
		*/
		void error(const CFStringRef& msg) const;
#endif

		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>FATAL</code>
		enabled by comparing the level of this logger with the
		FATAL level. If this logger is
		<code>FATAL</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const std::string& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const std::string& msg) const;
#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const std::wstring& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const std::wstring& msg) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const std::basic_string<UniChar>& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const std::basic_string<UniChar>& msg) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c msg and \c location to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const CFStringRef& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>FATAL</code> events.

		<p>This method first checks if this logger is <code>ERROR</code>
		enabled by comparing the level of this logger with the
		ERROR level. If this logger is
		<code>ERROR</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_FATAL.
		*/
		void fatal(const CFStringRef& msg) const;
#endif

		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addEvent(const LevelPtr& level, std::string&& message
			, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new fatal level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addFatalEvent(std::string&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new error level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addErrorEvent(std::string&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new warning level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addWarnEvent(std::string&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new info level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addInfoEvent(std::string&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new debug level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addDebugEvent(std::string&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new trace level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addTraceEvent(std::string&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void forcedLog(const LevelPtr& level, const std::string& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		*/
		void forcedLog(const LevelPtr& level, const std::string& message) const;

#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addEvent(const LevelPtr& level, std::wstring&& message
			, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new fatal level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addFatalEvent(std::wstring&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new error level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addErrorEvent(std::wstring&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new warning level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addWarnEvent(std::wstring&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new info level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addInfoEvent(std::wstring&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new debug level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addDebugEvent(std::wstring&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new trace level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addTraceEvent(std::wstring&& message, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void forcedLog(const LevelPtr& level, const std::wstring& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		*/
		void forcedLog(const LevelPtr& level, const std::wstring& message) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addEvent(const LevelPtr& level, std::basic_string<UniChar>&& message,
			const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;
		/**
		Add a new fatal level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addFatalEvent(std::basic_string<UniChar>&& message,const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;
		/**
		Add a new error level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addErrorEvent(std::basic_string<UniChar>&& message,const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;
		/**
		Add a new warning level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addWarnEvent(std::basic_string<UniChar>&& message,const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;
		/**
		Add a new info level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addInfoEvent(std::basic_string<UniChar>&& message,const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;
		/**
		Add a new debug level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addDebugEvent(std::basic_string<UniChar>&& message,const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;
		/**
		Add a new trace level logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void addTraceEvent(std::basic_string<UniChar>&& message,const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void forcedLog(const LevelPtr& level, const std::basic_string<UniChar>& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		*/
		void forcedLog(const LevelPtr& level, const std::basic_string<UniChar>& message) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		@param location The source code location of the logging request.
		*/
		void forcedLog(const LevelPtr& level, const CFStringRef& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message The text to add to the logging event.
		*/
		void forcedLog(const LevelPtr& level, const CFStringRef& message) const;
#endif
		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message the message string to log.
		@param location location of the logging statement.
		*/
		void addEventLS(const LevelPtr& level, LogString&& message
			, const spi::LocationInfo& location = spi::LocationInfo::getLocationUnavailable()) const;

		/**
		Add a new logging event containing \c message and \c location to attached appender(s)
		without further checks.
		@param level The logging event level.
		@param message the message string to log.
		@param location location of the logging statement.
		*/
		void forcedLogLS(const LevelPtr& level, const LogString& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;

		/**
		Get the additivity flag for this logger.
		*/
		bool getAdditivity() const;

		/**
		Get the appenders contained in this logger as an AppenderList.
		If no appenders can be found, then an empty AppenderList
		is returned.
		@return AppenderList An collection of the appenders in this logger.*/
		AppenderList getAllAppenders() const override;

		/**
		Look for the appender named as <code>name</code>.
		<p>Return the appender with that name if in the list. Return
		<code>NULL</code> otherwise.  */
		AppenderPtr getAppender(const LogString& name) const override;

		/**
		Starting from this logger, search the logger hierarchy for a
		non-null level and return it.

		<p>The Logger class is designed so that this method executes as
		quickly as possible.

		@throws RuntimeException if all levels are null in the hierarchy
		*/
		virtual const LevelPtr& getEffectiveLevel() const;

		/**
		Return the the LoggerRepository where this
		<code>Logger</code> is attached.
		*/
		LOG4CXX_NS::spi::LoggerRepository* getLoggerRepository() const;


		/**
		* Get the logger name.
		* @return logger name as LogString.
		*/
		const LogString& getName() const;

		/**
		* Put name of this logger into \c name in current encoding.
		* @param name buffer to which name is appended.
		*/
		void getName(std::string& name) const;
#if LOG4CXX_WCHAR_T_API
		/**
		* Put name of this logger into \c name.
		* @param name buffer to which name is appended.
		*/
		void getName(std::wstring& name) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		* Put name of this logger into \c name.
		* @param name buffer to which name is appended.
		*/
		void getName(std::basic_string<UniChar>& name) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		* Put name of this logger into \c name.
		* @param name buffer to which name is appended.
		*/
		void getName(CFStringRef& name) const;
#endif

		/**
		The parent of this logger. Note that the parent of a
		given logger may change during the lifetime of the logger.

		<p>The root logger will return <code>0</code>.
		*/
		LoggerPtr getParent() const;


		/**
		The assigned Level, if any, for this logger.

		@return Level - the assigned Level, can be null.
		*/
		const LevelPtr& getLevel() const;

		/**
		* Retrieve a logger by name in current encoding.
		* @param name logger name.
		*/
		static LoggerPtr getLogger(const std::string& name);
		/**
		* Retrieve a logger by name in current encoding.
		* @param name logger name.
		*/
		static LoggerPtr getLogger(const char* const name);
#if LOG4CXX_WCHAR_T_API
		/**
		* Retrieve a logger by name.
		* @param name logger name.
		*/
		static LoggerPtr getLogger(const std::wstring& name);
		/**
		* Retrieve a logger by name.
		* @param name logger name.
		*/
		static LoggerPtr getLogger(const wchar_t* const name);
#endif
#if LOG4CXX_UNICHAR_API
		/**
		* Retrieve a logger by name.
		* @param name logger name.
		*/
		static LoggerPtr getLogger(const std::basic_string<UniChar>& name);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		* Retrieve a logger by name.
		* @param name logger name.
		*/
		static LoggerPtr getLogger(const CFStringRef& name);
#endif
		/**
		* Retrieve a logger by name in Unicode.
		* @param name logger name.
		*/
		static LoggerPtr getLoggerLS(const LogString& name);

		/**
		Retrieve the root logger.
		*/
		static LoggerPtr getRootLogger();

		/**
		Like #getLogger except that the type of logger
		instantiated depends on the type returned by the
		LoggerFactory#makeNewLoggerInstance method of the
		<code>factory</code> parameter.

		<p>This method is intended to be used by sub-classes.

		@param name The name of the logger to retrieve.

		@param factory A LoggerFactory implementation that will
		actually create a new Instance.
		*/
		static LoggerPtr getLoggerLS(const LogString& name,
			const LOG4CXX_NS::spi::LoggerFactoryPtr& factory);
		/**
		Like #getLogger except that the type of logger
		instantiated depends on the type returned by the
		LoggerFactory#makeNewLoggerInstance method of the
		<code>factory</code> parameter.

		<p>This method is intended to be used by sub-classes.

		@param name The name of the logger to retrieve.

		@param factory A LoggerFactory implementation that will
		actually create a new Instance.
		*/
		static LoggerPtr getLogger(const std::string& name,
			const LOG4CXX_NS::spi::LoggerFactoryPtr& factory);
#if LOG4CXX_WCHAR_T_API
		/**
		Like #getLogger except that the type of logger
		instantiated depends on the type returned by the
		LoggerFactory#makeNewLoggerInstance method of the
		<code>factory</code> parameter.

		<p>This method is intended to be used by sub-classes.

		@param name The name of the logger to retrieve.

		@param factory A LoggerFactory implementation that will
		actually create a new Instance.
		*/
		static LoggerPtr getLogger(const std::wstring& name,
			const LOG4CXX_NS::spi::LoggerFactoryPtr& factory);
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Like #getLogger except that the type of logger
		instantiated depends on the type returned by the
		LoggerFactory#makeNewLoggerInstance method of the
		<code>factory</code> parameter.

		<p>This method is intended to be used by sub-classes.

		@param name The name of the logger to retrieve.

		@param factory A LoggerFactory implementation that will
		actually create a new Instance.
		*/
		static LoggerPtr getLogger(const std::basic_string<UniChar>& name,
			const LOG4CXX_NS::spi::LoggerFactoryPtr& factory);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Like #getLogger except that the type of logger
		instantiated depends on the type returned by the
		LoggerFactory#makeNewLoggerInstance method of the
		<code>factory</code> parameter.

		<p>This method is intended to be used by sub-classes.

		@param name The name of the logger to retrieve.

		@param factory A LoggerFactory implementation that will
		actually create a new Instance.
		*/
		static LoggerPtr getLogger(const CFStringRef& name,
			const LOG4CXX_NS::spi::LoggerFactoryPtr& factory);
#endif

		/**
		Return the <em>inherited</em> ResourceBundle for this logger.


		This method walks the hierarchy to find the appropriate resource bundle.
		It will return the resource bundle attached to the closest ancestor of
		this logger, much like the way priorities are searched. In case there
		is no bundle in the hierarchy then <code>NULL</code> is returned.
		*/
		helpers::ResourceBundlePtr getResourceBundle() const;

	protected:
		/**
		Returns the string resource corresponding to <code>key</code> in this
		logger's inherited resource bundle.

		If the resource cannot be found, then an {@link #error error} message
		will be logged complaining about the missing resource.

		@see #getResourceBundle.
		*/
		LogString getResourceBundleString(const LogString& key) const;

	public:
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_INFO.
		*/
		void info(const std::string& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_INFO.
		*/
		void info(const std::string& msg) const;
#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_INFO.
		*/
		void info(const std::wstring& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_INFO.
		*/
		void info(const std::wstring& msg) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.
		        */
		void info(const std::basic_string<UniChar>& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_INFO.
		*/
		void info(const std::basic_string<UniChar>& msg) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_INFO.
		*/
		void info(const CFStringRef& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>INFO</code> events.

		<p>This method first checks if this logger is <code>INFO</code>
		enabled by comparing the level of this logger with the
		INFO level. If this logger is
		<code>INFO</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_INFO.
		*/
		void info(const CFStringRef& msg) const;
#endif

		/**
		Is \c appender attached to this logger?
		*/
		bool isAttached(const AppenderPtr appender) const override;

		/**
		 *  Is this logger is enabled for <code>DEBUG</code> level logging events?
		 *
		 *  <p>By writing
		 *  ~~~{.cpp}
		 *  if(logger->isDebugEnabled()) {
		 *      logger->debug("Component: " + std::to_string(componentNumber));
		 *    }
		 *  ~~~
		 *  you will not incur the cost of parameter construction
		 *  (integer to string conversion plus string concatonation in this case)
		 *  if debugging is disabled for <code>logger</code>.
		 *  You avoid the cost constructing the message
		 *  when the message is not logged.
		 *
		 *  <p>This function allows you to reduce the computational cost of
		 *  disabled log debug statements compared to writing:
		 *  ~~~{.cpp}
		 *      logger->debug("Component: " + std::to_string(componentNumber));
		 *  ~~~
		 *
		 *  <p>On the other hand, if the <code>logger</code> is enabled for <code>DEBUG</code> logging events,
		 *  you will incur the cost of evaluating whether the logger is
		 *  enabled twice, once in <code>isDebugEnabled</code> and once in
		 *  the <code>DEBUG</code>.  This really is an insignificant overhead
		 *  since evaluating a the enabled status takes about 1% of the time it
		 *  takes to send the message to the appender.

		 * See also #isDebugEnabledFor.
		 * See also #LOG4CXX_DEBUG.
		 *
		 *  @return bool - <code>true</code> if this logger is debug
		 *  enabled, <code>false</code> otherwise.
		 **/
		bool isDebugEnabled() const;

		/**
		 *  Is \c logger is enabled for <code>DEBUG</code> level logging events?
		 *
		 *  <p>By writing
		 *  ~~~{.cpp}
		 *    if(log4cxx::Logger::isDebugEnabledFor(logger)) {
		 *      logger->addDebugEvent("Component: " + std::to_string(componentNumber));
		 *    }
		 *  ~~~
		 *  you minimise the computational cost
		 *  when \c logger is not enabled for <code>DEBUG</code> logging events.
		 *  This function may be inlined thereby avoiding a function call
		 *  as well as the cost constructing the message
		 *  when \c logger is not enabled for <code>DEBUG</code> events.
		 *
		 * See also #LOG4CXX_DEBUG.
		 *
		 *  @return bool - <code>false</code> if \c logger is <code>null</code>
		 *  or <code>DEBUG</code> logging events are disabled for \c logger,
		 *  <code>true</code> otherwise.
		 **/
		inline static bool isDebugEnabledFor(const LoggerPtr& logger)
		{
			return logger && logger->m_threshold <= Level::DEBUG_INT && logger->isDebugEnabled();
		}

		/**
		Is this logger is enabled for logging events at \c level?

		@return bool True if this logger is enabled for <code>level</code> logging events.
		*/
		bool isEnabledFor(const LevelPtr& level) const;


		/**
		Is this logger is enabled for <code>INFO</code> level logging events?

		See #isDebugEnabled.
		See also #LOG4CXX_INFO.

		@return bool - <code>true</code> if this logger is enabled
		for level info, <code>false</code> otherwise.
		*/
		bool isInfoEnabled() const;

		/**
		Is \c logger is enabled for <code>INFO</code> level logging events?

		See #isDebugEnabledFor.
		See also #LOG4CXX_INFO.

		@return bool - <code>false</code> if \c logger is <code>null</code>
		or <code>INFO</code> logging events are disabled for \c logger,
		<code>true</code> otherwise.
		*/
		inline static bool isInfoEnabledFor(const LoggerPtr& logger)
		{
			return logger && logger->m_threshold <= Level::INFO_INT && logger->isInfoEnabled();
		}

		/**
		Is this logger is enabled for <code>WARN</code> level logging events?

		See also #isDebugEnabled.
		See also #LOG4CXX_WARN.

		@return bool - <code>true</code> if this logger is enabled
		for level warn, <code>false</code> otherwise.
		*/
		bool isWarnEnabled() const;

		/**
		Is \c logger is enabled for <code>WARN</code> level logging events?

		See #isDebugEnabledFor.
		See also #LOG4CXX_WARN.

		@return bool - <code>false</code> if \c logger is <code>null</code>
		or <code>WARN</code> logging events are disabled for \c logger,
		<code>true</code> otherwise.
		*/
		inline static bool isWarnEnabledFor(const LoggerPtr& logger)
		{
			return logger && logger->m_threshold <= Level::WARN_INT && logger->isWarnEnabled();
		}

		/**
		Is this logger is enabled for <code>ERROR</code> level logging events?

		See also #isDebugEnabled.
		See also #LOG4CXX_ERROR.

		@return bool - <code>true</code> if this logger is enabled
		for level error, <code>false</code> otherwise.
		*/
		bool isErrorEnabled() const;

		/**
		Is \c logger is enabled for <code>ERROR</code> level logging events?

		See #isDebugEnabledFor.
		See also #LOG4CXX_ERROR.

		@return bool - <code>false</code> if \c logger is <code>null</code>
		or <code>ERROR</code> logging events are disabled for \c logger,
		<code>true</code> otherwise.
		*/
		inline static bool isErrorEnabledFor(const LoggerPtr& logger)
		{
			return logger && logger->m_threshold <= Level::ERROR_INT && logger->isErrorEnabled();
		}

		/**
		Is this logger is enabled for <code>FATAL</code> level logging events?

		See also #isDebugEnabled.
		See also #LOG4CXX_FATAL.

		@return bool - <code>true</code> if this logger is enabled
		for level fatal, <code>false</code> otherwise.
		*/
		bool isFatalEnabled() const;

		/**
		Is \c logger is enabled for <code>FATAL</code> level logging events?

		See #isDebugEnabledFor.
		See also #LOG4CXX_FATAL.

		@return bool - <code>false</code> if \c logger is <code>null</code>
		or <code>FATAL</code> logging events are disabled for \c logger,
		<code>true</code> otherwise.
		*/
		inline static bool isFatalEnabledFor(const LoggerPtr& logger)
		{
			return logger && logger->m_threshold <= Level::FATAL_INT && logger->isFatalEnabled();
		}

		/**
		Is this logger is enabled for <code>TRACE</code> level logging events?

		See also #isDebugEnabled.
		See also #LOG4CXX_FATAL.

		@return bool - <code>true</code> if this logger is enabled
		for level trace, <code>false</code> otherwise.
		*/
		bool isTraceEnabled() const;

		/**
		Is \c logger is enabled for <code>TRACE</code> level logging events?

		See #isDebugEnabledFor.
		See also #LOG4CXX_TRACE.

		@return bool - <code>false</code> if \c logger is <code>null</code>
		or <code>TRACE</code> logging events are disabled for \c logger,
		<code>true</code> otherwise.
		*/
		inline static bool isTraceEnabledFor(const LoggerPtr& logger)
		{
			return logger && logger->m_threshold <= Level::TRACE_INT && logger->isTraceEnabled();
		}

		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using \c values for parameter substitution
		to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param values The values for the placeholders <code>{0}</code>,
		              <code>{1}</code> etc. within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG1.
		*/
		void l7dlog(const LevelPtr& level, const LogString& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::vector<LogString>& values) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG.
		*/
		void l7dlog(const LevelPtr& level, const std::string& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameter \c val to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val The first value for the placeholders within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG1.
		*/
		void l7dlog(const LevelPtr& level, const std::string& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::string& val) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1 and \c val2 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The first value for the placeholders within the pattern.
		@param val2 The second value for the placeholders within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG2.
		*/
		void l7dlog(const LevelPtr& level, const std::string& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::string& val1, const std::string& val2) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1, \c val2 and \c val3 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.
		@param val2 The value for the second placeholder within the pattern.
		@param val3 The value for the third placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG3.
		*/
		void l7dlog(const LevelPtr& level, const std::string& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::string& val1, const std::string& val2, const std::string& val3) const;

#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method .

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG.
		*/
		void l7dlog(const LevelPtr& level, const std::wstring& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameter \c val to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameter in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val The value for the first placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG1.
		*/
		void l7dlog(const LevelPtr& level, const std::wstring& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::wstring& val) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1 and \c val2 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.
		@param val2 The value for the second placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG2.
		*/
		void l7dlog(const LevelPtr& level, const std::wstring& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::wstring& val1, const std::wstring& val2) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1, \c val2 and \c val3 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.
		@param val2 The value for the second placeholder within the pattern.
		@param val3 The value for the third placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG3.
		*/
		void l7dlog(const LevelPtr& level, const std::wstring& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::wstring& val1, const std::wstring& val2, const std::wstring& val3) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG.
		*/
		void l7dlog(const LevelPtr& level, const std::basic_string<UniChar>& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameter \c val to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameter in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val The value for the first placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG1.
		*/
		void l7dlog(const LevelPtr& level, const std::basic_string<UniChar>& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::basic_string<UniChar>& val) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1 and \c val2 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.
		@param val2 The value for the second placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG2.
		*/
		void l7dlog(const LevelPtr& level, const std::basic_string<UniChar>& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::basic_string<UniChar>& val1, const std::basic_string<UniChar>& val2) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1, \c val2 and \c val3 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.
		@param val2 The value for the second placeholder within the pattern.
		@param val3 The value for the third placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG3.
		*/
		void l7dlog(const LevelPtr& level, const std::basic_string<UniChar>& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const std::basic_string<UniChar>& val1, const std::basic_string<UniChar>& val2,
			const std::basic_string<UniChar>& val3) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG.
		*/
		void l7dlog(const LevelPtr& level, const CFStringRef& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameter \c val to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameter in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG1.
		*/
		void l7dlog(const LevelPtr& level, const CFStringRef& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const CFStringRef& val1) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1 and \c val2 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.
		@param val2 The value for the second placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG2.
		*/
		void l7dlog(const LevelPtr& level, const CFStringRef& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const CFStringRef& val1, const CFStringRef& val2) const;
		/**
		Add a new logging event containing \c locationInfo and the localized message \c key using parameters \c val1, \c val2 and \c val3 to attached appender(s) if this logger is enabled for \c level events.

		First, the user supplied
		<code>key</code> is searched in the resource bundle. Next, the resulting
		pattern is formatted using helpers::StringHelper::format method with the
		supplied parameters in a string array.

		@param level The level of the logging request.
		@param key The key to be searched in the ResourceBundle.
		@param locationInfo The location info of the logging request.
		@param val1 The value for the first placeholder within the pattern.
		@param val2 The value for the second placeholder within the pattern.
		@param val3 The value for the third placeholder within the pattern.

		@see #setResourceBundle

		See also #LOG4CXX_L7DLOG3.
		*/
		void l7dlog(const LevelPtr& level, const CFStringRef& key,
			const LOG4CXX_NS::spi::LocationInfo& locationInfo,
			const CFStringRef& val1, const CFStringRef& val2,
			const CFStringRef& val3) const;
#endif

		/**
		Add a new logging event containing \c message and \c location to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		@param location The source file of the logging request, may be null. */
		void log(const LevelPtr& level, const std::string& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		*/
		void log(const LevelPtr& level, const std::string& message) const;
#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c message and \c location to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		@param location The source file of the logging request, may be null. */
		void log(const LevelPtr& level, const std::wstring& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		*/
		void log(const LevelPtr& level, const std::wstring& message) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c message and \c location to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		@param location The source file of the logging request, may be null. */
		void log(const LevelPtr& level, const std::basic_string<UniChar>& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		*/
		void log(const LevelPtr& level, const std::basic_string<UniChar>& message) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c message and \c location to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		@param location The source file of the logging request, may be null. */
		void log(const LevelPtr& level, const CFStringRef& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c message to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		*/
		void log(const LevelPtr& level, const CFStringRef& message) const;
#endif
		/**
		Add a new logging event containing \c message and \c location to the appenders attached to this logger if this logger is enabled for \c level events.
		This is the most generic printing method. It is intended to be
		invoked by <b>wrapper</b> classes.

		@param level The level of the logging request.
		@param message The message of the logging request.
		@param location The source file of the logging request, may be null. */
		void logLS(const LevelPtr& level, const LogString& message,
			const LOG4CXX_NS::spi::LocationInfo& location) const;



		/**
		Remove all previously added appenders from this logger
		instance.
		<p>This is useful when re-reading configuration information.
		*/
		void removeAllAppenders() override;

		/**
		Remove the appender passed as parameter form the list of appenders.
		*/
		void removeAppender(const AppenderPtr appender) override;

		/**
		Remove the appender with the name passed as parameter form the
		list of appenders.
		 */
		void removeAppender(const LogString& name) override;

		/**
		 Set the additivity flag for this logger.
		  */
		void setAdditivity(bool additive);

	protected:
		friend class Hierarchy;
		/**
		Only the Hierarchy class can remove the hierarchy of a logger.
		*/
		void removeHierarchy();
		/**
		Only the Hierarchy class can set the hierarchy of a logger.
		*/
		void setHierarchy(spi::LoggerRepository* repository);
		/**
		Only the Hierarchy class can set the parent of a logger.
		*/
		void setParent(LoggerPtr parentLogger);
		/**
		Only the Hierarchy class can change the threshold of a logger.
		*/
		void updateThreshold();

	private:
		spi::LoggerRepository* getHierarchy() const;

	public:
		/**
		Set the level of this logger.

		<p>As in <code>logger->setLevel(Level::getDebug());</code>

		<p>Null values are admitted.  */
		virtual void setLevel(const LevelPtr level);

		/**
		Set the resource bundle to be used with localized logging methods.
		*/
		void setResourceBundle(const helpers::ResourceBundlePtr& bundle);

#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_WARN.
		*/
		void warn(const std::wstring& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_WARN.
		*/
		void warn(const std::wstring& msg) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_WARN.
		*/
		void warn(const std::basic_string<UniChar>& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_WARN.
		*/
		void warn(const std::basic_string<UniChar>& msg) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_WARN.
		*/
		void warn(const CFStringRef& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_WARN.
		*/
		void warn(const CFStringRef& msg) const;
#endif
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_WARN.
		*/
		void warn(const std::string& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>WARN</code> events.

		<p>This method first checks if this logger is <code>WARN</code>
		enabled by comparing the level of this logger with the
		WARN level. If this logger is
		<code>WARN</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_WARN.
		*/
		void warn(const std::string& msg) const;

#if LOG4CXX_WCHAR_T_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const std::wstring& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const std::wstring& msg) const;
#endif
#if LOG4CXX_UNICHAR_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const std::basic_string<UniChar>& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const std::basic_string<UniChar>& msg) const;
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const CFStringRef& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const CFStringRef& msg) const;
#endif
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.
		@param location The source code location of the logging request.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const std::string& msg, const LOG4CXX_NS::spi::LocationInfo& location) const;
		/**
		Add a new logging event containing \c msg to attached appender(s) if this logger is enabled for <code>TRACE</code> events.

		<p>This method first checks if this logger is <code>TRACE</code>
		enabled by comparing the level of this logger with the
		TRACE level. If this logger is
		<code>TRACE</code> enabled, it proceeds to call all the
		registered appenders in this logger and also higher in the
		hierarchy depending on the value of the additivity flag.

		@param msg the message string to log.

		See also #LOG4CXX_TRACE.
		*/
		void trace(const std::string& msg) const;

		/**
		 * Reconfigure this logger by configuring all of the appenders.
		 *
		 * @param appenders The appenders to set.  Any currently existing appenders are removed.
		 * @param additivity The additivity of this logger
		 */
		void reconfigure( const std::vector<AppenderPtr>& appenders, bool additivity );

	private:
		//
		//  prevent copy and assignment
		Logger(const Logger&);
		Logger& operator=(const Logger&);
};
LOG4CXX_LIST_DEF(LoggerList, LoggerPtr);
}

#if !defined(LOG4CXX_UNLIKELY)
	#if __GNUC__ >= 3
		/**
		Provides optimization hint to the compiler
		to optimize for the expression being false.
		@param expr boolean expression.
		@returns value of expression.
		*/
		#define LOG4CXX_UNLIKELY(expr) __builtin_expect(expr, 0)
	#else
		/**
		Provides optimization hint to the compiler
		to optimize for the expression being false.
		@param expr boolean expression.
		@returns value of expression.
		**/
		#define LOG4CXX_UNLIKELY(expr) expr
	#endif
#endif

#if defined(LOG4CXX_ENABLE_STACKTRACE) && !defined(LOG4CXX_STACKTRACE)
	#ifndef __has_include
		#include <boost/stacktrace.hpp>
		#define LOG4CXX_STACKTRACE ::LOG4CXX_NS::MDC mdc_("stacktrace", LOG4CXX_EOL + boost::stacktrace::to_string(boost::stacktrace::stacktrace()));
	#elif __has_include(<stacktrace>)
		#include <stacktrace>
		#define LOG4CXX_STACKTRACE ::LOG4CXX_NS::MDC mdc_("stacktrace", LOG4CXX_EOL + std::stacktrace::to_string(std::stacktrace::stacktrace()));
	#elif __has_include(<boost/stacktrace.hpp>)
		#include <boost/stacktrace.hpp>
		#define LOG4CXX_STACKTRACE ::LOG4CXX_NS::MDC mdc_("stacktrace", LOG4CXX_EOL + boost::stacktrace::to_string(boost::stacktrace::stacktrace()));
	#else
		#warning "Stacktrace requested but no implementation found"
	#endif
#endif /* LOG4CXX_ENABLE_STACKTRACE */

#if !defined(LOG4CXX_STACKTRACE)
#define LOG4CXX_STACKTRACE
#endif

#ifndef LOG4CXX_FMT_VA_ARG
#if __cplusplus >= 202002L
	#define LOG4CXX_FMT_VA_ARG(...) __VA_OPT__(,) __VA_ARGS__
#else
	#define LOG4CXX_FMT_VA_ARG(...) , __VA_ARGS__
#endif
#endif

/** @addtogroup LoggingMacros Logging macros
@{
*/

/**
Add a new logging event containing \c message to attached appender(s) if this logger is enabled for \c events.

@param logger the logger to be used.
@param level The logging event level.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_LOG(logger, level, message) do { \
		if (logger->isEnabledFor(level)) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			logger->addEvent(level, oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing a message defined by \c fmt and <code>...</code> to attached appender(s) if this logger is enabled for \c events.

@param logger the logger to be used.
@param level The logging event level.
@param fmt the layout of the message.
@param ... the variable parts of the message.
*/
#define LOG4CXX_LOG_FMT(logger, level, fmt, ...) do { \
		if (logger->isEnabledFor(level)) {\
			logger->addEvent(level, ::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__) ), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing \c message to attached appender(s) if this logger is enabled for \c events.

@param logger the logger to be used.
@param level The logging event level.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload. in the internal encoding.
*/
#define LOG4CXX_LOGLS(logger, level, message) do { \
		if (logger->isEnabledFor(level)) {\
			::LOG4CXX_NS::helpers::LogCharMessageBuffer oss_; \
			logger->addEvent(level, oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 10000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>DEBUG</code> events.

\usage
~~~{.cpp}
LOG4CXX_DEBUG(m_log, "AddMesh:"
	<< " name " << meshName
	<< " type 0x" << std:: hex << traits.Type
	<< " materialName " << meshObject.GetMaterialName()
	<< " visible? " << traits.IsDefaultVisible
	<< " at " << obj->getBoundingBox().getCenter()
	<< " +/- " << obj->getBoundingBox().getHalfSize()
	);
~~~

@param logger the logger that has the enabled status.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.

*/
#define LOG4CXX_DEBUG(logger, message) do { \
		if (LOG4CXX_UNLIKELY(::LOG4CXX_NS::Logger::isDebugEnabledFor(logger))) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			logger->addDebugEvent(oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing a message defined by \c fmt and <code>...</code> to attached appender(s) if \c logger is enabled for <code>DEBUG</code> events.

\usage
~~~{.cpp}
LOG4CXX_DEBUG_FMT(m_log, "AddMesh: name {} type 0x{x} materialName {} visible? {d} at {} +/- {}"
	, meshName
	, traits.Type
	, meshObject.GetMaterialName()
	, traits.IsDefaultVisible
	, obj->getBoundingBox().getCenter()
	, obj->getBoundingBox().getHalfSize()
	);
~~~

@param logger the logger to be used.
@param fmt the layout of the message.
@param ... the variable parts of the message.
*/
#define LOG4CXX_DEBUG_FMT(logger, fmt, ...) do { \
		if (LOG4CXX_UNLIKELY(::LOG4CXX_NS::Logger::isDebugEnabledFor(logger))) {\
			logger->addDebugEvent(::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__) ), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_DEBUG(logger, message)
#define LOG4CXX_DEBUG_FMT(logger, fmt, ...)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 5000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>TRACE</code> events.

\usage
~~~{.cpp}
    LOG4CXX_TRACE(m_log, "AddVertex:" << " at " << p << " n " << n << ' ' << color);
~~~

@param logger the logger that has the enabled status.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_TRACE(logger, message) do { \
		if (LOG4CXX_UNLIKELY(::LOG4CXX_NS::Logger::isTraceEnabledFor(logger))) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			logger->addTraceEvent(oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing a message defined by \c fmt and <code>...</code> to attached appender(s) if \c logger is enabled for <code>TRACE</code> events.

\usage
~~~{.cpp}
    LOG4CXX_TRACE_FMT(m_log, "AddVertex: at {} n {} {}", p, n, color);
~~~

@param logger the logger to be used.
@param fmt the layout of the message.
@param ... the variable parts of the message.
*/
#define LOG4CXX_TRACE_FMT(logger, fmt, ...) do { \
		if (LOG4CXX_UNLIKELY(::LOG4CXX_NS::Logger::isTraceEnabledFor(logger))) {\
			logger->addTraceEvent(::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__)), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_TRACE(logger, message)
#define LOG4CXX_TRACE_FMT(logger, fmt, ...)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 20000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>INFO</code> events.

\usage
~~~{.cpp}
LOG4CXX_INFO(m_log, surface->GetName()
	<< " successfully planned " << std::fixed << std::setprecision(1) << ((plannedArea  / (plannedArea + unplannedArea)) * 100.0) << "%"
	<< " planned area " << std::fixed << std::setprecision(4) << plannedArea << "m^2"
	<< " unplanned area " << unplannedArea << "m^2"
	<< " planned segments " << surface->GetSegmentPlanCount() << " of " << surface->GetSegmentCount()
	);
~~~

@param logger the logger that has the enabled status.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_INFO(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isInfoEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			logger->addInfoEvent(oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing a message defined by \c fmt and <code>...</code> to attached appender(s) if \c logger is enabled for <code>INFO</code> events.

\usage
~~~{.cpp}
LOG4CXX_INFO_FMT(m_log, "{} successfully planned {:.1f}% planned area {:.4f}m^2 unplanned area {:.4f}m^2 planned segments {:d} of {:d}"
    , surface->GetName(), (plannedArea  / (plannedArea + unplannedArea)) * 100.0
	, plannedArea, unplannedArea
	, surface->GetSegmentPlanCount(), surface->GetSegmentCount()
	);
~~~

@param logger the logger to be used.
@param fmt the layout of the message.
@param ... the variable parts of the message.
*/
#define LOG4CXX_INFO_FMT(logger, fmt, ...) do { \
		if (::LOG4CXX_NS::Logger::isInfoEnabledFor(logger)) {\
			logger->addInfoEvent(::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__)), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_INFO(logger, message)
#define LOG4CXX_INFO_FMT(logger, fmt, ...)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 30000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>WARN</code> events.

\usage
~~~{.cpp}
catch (const std::exception& ex)
{
    LOG4CXX_WARN(m_log, ex.what() << ": in " << m_task->GetParamFilePath());
}
~~~

@param logger the logger to be used.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_WARN(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isWarnEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			logger->addWarnEvent(oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing a message defined by \c fmt and <code>...</code> to attached appender(s) if \c logger is enabled for <code>WARN</code> events.

\usage
~~~{.cpp}
catch (const std::exception& ex)
{
    LOG4CXX_WARN_FMT(m_log, "{}: in {}", ex.what(), m_task->GetParamFilePath());
}
~~~

@param logger the logger to be used.
@param fmt the layout of the message.
@param ... the variable parts of the message.
*/
#define LOG4CXX_WARN_FMT(logger, fmt, ...) do { \
		if (::LOG4CXX_NS::Logger::isWarnEnabledFor(logger)) {\
			logger->addWarnEvent(::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__)), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_WARN(logger, message)
#define LOG4CXX_WARN_FMT(logger, fmt, ...)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 40000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>ERROR</code> events.

\usage
~~~{.cpp}
catch (std::exception& ex)
{
	LOG4CXX_ERROR(m_log, ex.what() << " in AddScanData");
}
~~~

@param logger the logger to be used.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_ERROR(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isErrorEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			logger->addErrorEvent(oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing a message defined by \c fmt and <code>...</code> to attached appender(s) if \c logger is enabled for <code>ERROR</code> events.

\usage
~~~{.cpp}
catch (std::exception& ex)
{
	LOG4CXX_ERROR_FMT(m_log, "{} in AddScanData", ex.what());
}
~~~

@param logger the logger to be used.
@param fmt the layout of the message.
@param ... the variable parts of the message.
*/
#define LOG4CXX_ERROR_FMT(logger, fmt, ...) do { \
		if (::LOG4CXX_NS::Logger::isErrorEnabledFor(logger)) {\
			logger->addErrorEvent(::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__)), LOG4CXX_LOCATION); }} while (0)

/**
If \c condition is not true, add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>ERROR</code> events.

@param logger the logger to be used.
@param condition condition
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_ASSERT(logger, condition, message) do { \
		if (!(condition) && ::LOG4CXX_NS::Logger::isErrorEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			LOG4CXX_STACKTRACE \
			logger->addErrorEvent(oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
If \c condition is not true, add a new logging event containing
a message defined by \c fmt and <code>...</code> to attached appender(s)
if \c logger is enabled for <code>ERROR</code> events.

@param logger the logger to be used.
@param condition condition
@param fmt the layout of the message.
@param ... the variable parts of the message.
*/
#define LOG4CXX_ASSERT_FMT(logger, condition, fmt, ...) do { \
		if (!(condition) && ::LOG4CXX_NS::Logger::isErrorEnabledFor(logger)) {\
			LOG4CXX_STACKTRACE \
			logger->addErrorEvent(::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__)), LOG4CXX_LOCATION); }} while (0)

#else
#define LOG4CXX_ERROR(logger, message)
#define LOG4CXX_ERROR_FMT(logger, fmt, ...)
#define LOG4CXX_ASSERT(logger, condition, message)
#define LOG4CXX_ASSERT_FMT(logger, condition, fmt, ...)
#endif

#if !defined(LOG4CXX_THRESHOLD) || LOG4CXX_THRESHOLD <= 50000
/**
Add a new logging event containing \c message to attached appender(s) if \c logger is enabled for <code>FATAL</code> events.

\usage
~~~{.cpp}
LOG4CXX_FATAL(m_log, m_renderSystem->getName() << " is not supported");
~~~

@param logger the logger to be used.
@param message a valid r-value expression of an <code>operator<<(std::ostream&. ...)</code> overload.
*/
#define LOG4CXX_FATAL(logger, message) do { \
		if (::LOG4CXX_NS::Logger::isFatalEnabledFor(logger)) {\
			::LOG4CXX_NS::helpers::MessageBuffer oss_; \
			logger->addFatalEvent(oss_.extract_str(oss_ << message), LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing a message defined by \c fmt and <code>...</code> to attached appender(s) if \c logger is enabled for <code>FATAL</code> events.

\usage
~~~{.cpp}
LOG4CXX_FATAL_FMT(m_log, "{} is not supported", m_renderSystem->getName());
~~~
@param logger the logger to be used.
@param fmt the layout of the message.
@param ... the variable parts of the message.

*/
#define LOG4CXX_FATAL_FMT(logger, fmt, ...) do { \
		if (::LOG4CXX_NS::Logger::isFatalEnabledFor(logger)) {\
			logger->addFatalEvent(::LOG4CXX_FORMAT_NS::format(fmt LOG4CXX_FMT_VA_ARG(__VA_ARGS__)), LOG4CXX_LOCATION); }} while (0)
#else
#define LOG4CXX_FATAL(logger, message)
#define LOG4CXX_FATAL_FMT(logger, fmt, ...)
#endif

/**
Add a new logging event containing the localized message \c key to attached appender(s) if \c logger is enabled for \c level events.

@param logger the logger to be used.
@param level The logging event level.
@param key the key to be searched in the resourceBundle of the logger.
*/
#define LOG4CXX_L7DLOG(logger, level, key) do { \
		if (logger->isEnabledFor(level)) {\
			logger->l7dlog(level, key, LOG4CXX_LOCATION); }} while (0)

/**
Add a new logging event containing the localized message \c key to attached appender(s) if \c logger is enabled for \c level events with one parameter.

@param logger the logger to be used.
@param level The logging event level.
@param key the key to be searched in the resourceBundle of the logger.
@param p1 the unique parameter.
*/
#define LOG4CXX_L7DLOG1(logger, level, key, p1) do { \
		if (logger->isEnabledFor(level)) {\
			logger->l7dlog(level, key, LOG4CXX_LOCATION, p1); }} while (0)

/**
Add a new logging event containing the localized message \c key to attached appender(s) if \c logger is enabled for \c level events with two parameters.

@param logger the logger to be used.
@param level The logging event level.
@param key the key to be searched in the resourceBundle of the logger.
@param p1 the first parameter.
@param p2 the second parameter.
*/
#define LOG4CXX_L7DLOG2(logger, level, key, p1, p2) do { \
		if (logger->isEnabledFor(level)) {\
			logger->l7dlog(level, key, LOG4CXX_LOCATION, p1, p2); }} while (0)

/**
Add a new logging event containing the localized message \c key to attached appender(s) if \c logger is enabled for \c level events with three parameters.

@param logger the logger to be used.
@param level The logging event level.
@param key the key to be searched in the resourceBundle of the logger.
@param p1 the first parameter.
@param p2 the second parameter.
@param p3 the third parameter.
*/
#define LOG4CXX_L7DLOG3(logger, level, key, p1, p2, p3) do { \
		if (logger->isEnabledFor(level)) {\
			logger->l7dlog(level, key, LOG4CXX_LOCATION, p1, p2, p3); }} while (0)

/**@}*/

#include <log4cxx/spi/loggerrepository.h>

#endif //_LOG4CXX_LOGGER_H
