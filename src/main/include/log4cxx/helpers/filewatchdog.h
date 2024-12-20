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
#include <time.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/file.h>

namespace LOG4CXX_NS
{
namespace helpers
{

/**
Check every now and then that a certain file has not changed. If it
has, then call the #doOnChange method.
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
		FileWatchdog(const File& filename);
		virtual void doOnChange() = 0;
		void checkAndConfigure();
		const File& file();

	public:
		/**
		Use \c delay as the number of milliseconds to wait between each check for file changes.
		*/
		void setDelay(long delay);

		/**
		Create an asynchronous task that periodically checks for a file change after first calling doOnChange().
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
	private:

		FileWatchdog(const FileWatchdog&);
		FileWatchdog& operator=(const FileWatchdog&);

		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(FileWatchdogPrivate, m_priv)
};
}  // namespace helpers
} // namespace log4cxx


#endif // _LOG4CXX_HELPERS_FILEWATCHDOG_H
