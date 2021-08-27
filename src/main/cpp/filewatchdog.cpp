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
#include <apr_time.h>
#include <apr_thread_proc.h>
#include <apr_atomic.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/threadutility.h>
#include <functional>

using namespace log4cxx;
using namespace log4cxx::helpers;

long FileWatchdog::DEFAULT_DELAY = 60000;

FileWatchdog::FileWatchdog(const File& file1)
	: file(file1), delay(DEFAULT_DELAY), lastModif(0),
	  warnedAlready(false), interrupted(0), thread()
{
}

FileWatchdog::~FileWatchdog()
{
	interrupted = 0xFFFF;

	{
		std::unique_lock<std::mutex> lock(interrupt_mutex);
		interrupt.notify_all();
	}
	thread.join();
}

void FileWatchdog::checkAndConfigure()
{
	Pool pool1;

	if (!file.exists(pool1))
	{
		if (!warnedAlready)
		{
			LogLog::debug(((LogString) LOG4CXX_STR("["))
				+ file.getPath()
				+ LOG4CXX_STR("] does not exist."));
			warnedAlready = true;
		}
	}
	else
	{
		apr_time_t thisMod = file.lastModified(pool1);

		if (thisMod > lastModif)
		{
			lastModif = thisMod;
			doOnChange();
			warnedAlready = false;
		}
	}
}

void FileWatchdog::run()
{

	while (interrupted != 0xFFFF)
	{
		std::unique_lock<std::mutex> lock( interrupt_mutex );
		interrupt.wait_for( lock, std::chrono::milliseconds( delay ),
			std::bind(&FileWatchdog::is_interrupted, this) );

		checkAndConfigure();
	}

}

void FileWatchdog::start()
{
	checkAndConfigure();

	thread = ThreadUtility::instance()->createThread( LOG4CXX_STR("FileWatchdog"), &FileWatchdog::run, this );
}

bool FileWatchdog::is_interrupted()
{
	return interrupted == 0xFFFF;
}
