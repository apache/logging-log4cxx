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

#ifndef _LOG4CXX_SPI_LOGGING_EVENT_H
#define _LOG4CXX_SPI_LOGGING_EVENT_H

#include <log4cxx/logstring.h>
#include <time.h>
#include <log4cxx/logger.h>
#include <log4cxx/mdc.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <vector>
#include <chrono>


namespace LOG4CXX_NS
{

namespace spi
{
LOG4CXX_LIST_DEF(KeySet, LogString);

/**
The data recorded for each logging request.
Each logging request instantiates a <code>LoggingEvent</code> instance,
which Log4cxx provides to [filters](@ref log4cxx.spi.Filter),
[layouts](@ref log4cxx.Layout) and [appenders](@ref log4cxx.Appender).

<p>This class is of concern to those wishing to extend log4cxx.
*/
class LOG4CXX_EXPORT LoggingEvent :
	public virtual helpers::Object
{
	public:
		DECLARE_LOG4CXX_OBJECT(LoggingEvent)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(LoggingEvent)
		END_LOG4CXX_CAST_MAP()

		typedef spi::KeySet KeySet;

		/** An empty event.
		*/
		LoggingEvent();

		/**
		An event composed using the supplied parameters.

		@param logger The logger used to make the logging request.
		@param level The severity of this event.
		@param location The source code location of the logging request.
		@param message  The text to add to this event.
		*/
		LoggingEvent
			( const LogString& logger
			, const LevelPtr& level
			, const LocationInfo& location
			, LogString&& message
			);

		/**
		An event composed using the supplied parameters.

		@param logger The logger used to make the logging request.
		@param level The severity of this event.
		@param message  The text to add to this event.
		@param location The source code location of the logging request.
		*/
		LoggingEvent
			( const LogString& logger
			, const LevelPtr&  level
			, const LogString& message
			, const LocationInfo& location
			);

		~LoggingEvent();

		/** The severity level of the logging request that generated this event. */
		const LevelPtr& getLevel() const;

		/**  The name of the logger used to make the logging request. */
		const LogString& getLoggerName() const;

		/** The message provided in the logging request. */
		const LogString& getMessage() const;

		/** The message provided in the logging request. */
		const LogString& getRenderedMessage() const;

		/** The number of microseconds elapsed since 1970-01-01
		 *  at the time the application started.
		 */
		static log4cxx_time_t getStartTime();

		/** The identity of the thread in which this logging event was created. */
		const LogString& getThreadName() const;

		/**
		 * The name you gave to the thread in which this logging event was created.
		 * You can create a named thread using log4cxx::helpers::ThreadUtility::createThread.
		 * If Log4cxx is unable to retrieve the thread name using a platform-specific call,
		 * the value is the same as the thread identity.
		 */
		const LogString& getThreadUserName() const;

		/** The number of microseconds elapsed since 1970-01-01
		 *  at the time this logging event was created.
		 */
		log4cxx_time_t getTimeStamp() const;

		/** The value of the system clock at the time this logging event was created.
		 */
		std::chrono::time_point<std::chrono::system_clock> getChronoTimeStamp() const;

		/** The source code location where the logging request was made. */
		const LocationInfo& getLocationInformation() const;

		/**
		* Add the current nested diagnostic context to the end of \c dest.
		* The diagnostic context must have been loaded into this LoggingEvent using LoadDC,
		* to obtain the correct content if the event was generated in a different thread.
		*
		* @param dest the string to be added to.
		* @return true if \c dest is changed.
		*/
		bool getNDC(LogString& dest) const;

		/**
		* Add the value associated with \c key to the end of \c dest.
		* The diagnostic context must have been loaded into this LoggingEvent using LoadDC,
		* to obtain the correct content if the event was generated in a different thread.
		*
		* @param key mapped diagnostic context key value.
		* @param dest the string to be added to.
		* @return true if \c dest is changed.
		*/
		bool getMDC(const LogString& key, LogString& dest) const;

		/**
		* The keys in the mapped diagnostic context for the event.
		*
		* @return the mapped diagnostic context keys.
		*
		*/
		KeySet getMDCKeySet() const;

#if LOG4CXX_ABI_VERSION <= 15
		/**
		Obtain a copy of the current thread's diagnostic context data.
		*/
		[[ deprecated( "Use LoadDC instead" ) ]]
		void getMDCCopy() const;
#endif

		/**
		* Obtain a copy of the current thread's diagnostic context data.
		* The diagnostic context must be loaded to ensure the
		* correct diagnostic context data is available
		* when the event is stored for later use
		* (for example, when the appender uses a different thread to process this event).
		*/
		void LoadDC() const;

		/**
		* Append onto \c dest the value associated with the property \c key.
		* @param key the property name.
		* @param dest the string onto which to associated value is appended.
		* @return true if \c dest was changed.
		*/
		bool getProperty(const LogString& key, LogString& dest) const;

		/**
		* The set of of the key values in the properties
		* for the event.
		* @return the keys from properties in this event.
		*/
		KeySet getPropertyKeySet() const;

		/**
		* Associate \c value with the property \c key.
		*/
		void setProperty(const LogString& key, const LogString& value);

	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(LoggingEventPrivate, m_priv)

		//
		//   prevent copy and assignment
		//
		LoggingEvent(const LoggingEvent&);
		LoggingEvent& operator=(const LoggingEvent&);

};

LOG4CXX_PTR_DEF(LoggingEvent);
LOG4CXX_LIST_DEF(LoggingEventList, LoggingEventPtr);
}
}

#endif //_LOG4CXX_SPI_LOGGING_EVENT_H
