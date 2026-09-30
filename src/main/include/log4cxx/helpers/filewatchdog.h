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

#ifndef _LOG4CXX_HELPERS_FILEWATCHDOG_H
#define _LOG4CXX_HELPERS_FILEWATCHDOG_H

#include <log4cxx/logstring.h>
#include <log4cxx/file.h>
#include <log4cxx/spi/configurator.h>

namespace LOG4CXX_NS
{
namespace helpers
{
class FileWatchdog;
LOG4CXX_PTR_DEF(FileWatchdog);

/**
A monitor that will periodically check if a nominated file has changed
and call the #doOnChange virtual method if it has.
*/
class LOG4CXX_EXPORT FileWatchdog
{
	public:
		virtual ~FileWatchdog();
		/**
		The default delay between every file modification check, set to 60
		seconds.  */
		static long DEFAULT_DELAY /*= 60000 ms*/;

	protected:
		/** Monitors \c filename and optionally uses \c processor to configure \c target
		*/
		FileWatchdog
			( const File&                     filename
			, const spi::ConfiguratorPtr&     processor = {}
			, const spi::LoggerRepositoryPtr& target = {}
			);

		/**	Call spi::Configurator::doConfigure if a processor has been provided.
		*/
		virtual void doOnChange();

		/** Call doOnChange() if the watched file has changed.
		*/
		void checkAndConfigure();

		/** The watched file.
		*/
		const File& file();

	public:
		/** A shareable pointer to this
		*/
		FileWatchdogPtr getSharedPtr();

		/** The result from the most recent call to spi::Configurator::doConfigure
		*/
		spi::ConfigurationStatus getStatus();

		/**
		Wait \c millisecondDelay between each check for file changes.
		*/
		void setDelay(long millisecondDelay);

		/**
		Change the watched file to \c filename.
		*/
		void setFile(const File& filename);

		/**
		Call checkAndConfigure() and then add an asynchronous task that periodically checks for a modification to file().
		*/
		void start();

		/**
		Stop the task that periodically checks for a file change.
		*/
		void stop();

		/**
		Is the task that periodically checks for a file change running?
		*/
		bool is_active();

		/**
		Stop all tasks that periodically check for a file change.
		*/
		static void stopAll();

		/**
		Call start() on a monitor of \c filename that uses \c processor to configure \c target
		*/
		static auto startWatching
			( const File&                     filename
			, const spi::ConfiguratorPtr&     processor
			, const spi::LoggerRepositoryPtr& target
			, long                            millisecondDelay
			) -> spi::ConfigurationStatus;
	private:

		FileWatchdog(const FileWatchdog&);
		FileWatchdog& operator=(const FileWatchdog&);

		struct FileWatchdogPrivate;
		LOG4CXX_DECLARE_PRIVATE_MEMBER(std::shared_ptr<FileWatchdogPrivate>, m_priv)
};
}  // namespace helpers
} // namespace log4cxx


#endif // _LOG4CXX_HELPERS_FILEWATCHDOG_H
