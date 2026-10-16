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

#if !defined(LOG4CXX_ROLLING_MULTIPROCESS_ROLLING_FILE_APPENDER_H)
#define LOG4CXX_ROLLING_MULTIPROCESS_ROLLING_FILE_APPENDER_H

#include <log4cxx/fileappender.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/rolling/triggeringpolicy.h>

namespace LOG4CXX_NS
{
namespace rolling
{


/**
 * A special version of the RollingFileAppender that acts properly with multiple processes.
 *
 * Coordinating with other processes adds significant overhead compared to RollingFileAppender.
 * Benchmarks show the overhead of this appender is more than 3 and 10 times
 * the overhead of RollingFileAppender on Linux and Windows respectively.
 *
 * Note: Do *not* set the option <code>Append</code> to <code>false</code>.
 * Rolling over files is only relevant when you are appending.
 */
class LOG4CXX_EXPORT MultiprocessRollingFileAppender : public RollingFileAppender
{
		DECLARE_LOG4CXX_OBJECT(MultiprocessRollingFileAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(MultiprocessRollingFileAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(RollingFileAppender)
		END_LOG4CXX_CAST_MAP()
	protected:
		struct MultiprocessRollingFileAppenderPriv;

	public:
		/**
		An unconfigured Appender.
		*/
		MultiprocessRollingFileAppender();

		using RollingFileAppender::activateOptions;
		/**
		\copybrief FileAppender::activateOptions()

		\sa FileAppender::activateOptions()
		*/
		void activateOptions(  ) override;

	protected:

		/**
		 Rollover the file if required before calling WriterAppender::subAppend.
		*/
		void subAppend( const spi::LoggingEventPtr& event ) override;

};

LOG4CXX_PTR_DEF(MultiprocessRollingFileAppender);

}
}

#endif

