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
		MultiprocessRollingFileAppender();

		/**
		\copybrief FileAppender::activateOptions()

		\sa FileAppender::activateOptions()
		*/
		void activateOptions(helpers::Pool& pool ) override;

		/**
		   Implements the usual roll over behaviour.

		   <p>If <code>MaxBackupIndex</code> is positive, then files
		   {<code>File.1</code>, ..., <code>File.MaxBackupIndex -1</code>}
		   are renamed to {<code>File.2</code>, ...,
		   <code>File.MaxBackupIndex</code>}. Moreover, <code>File</code> is
		   renamed <code>File.1</code> and closed. A new <code>File</code> is
		   created to receive further log output.

		   <p>If <code>MaxBackupIndex</code> is equal to zero, then the
		   <code>File</code> is truncated with no backup files created.

		 */
		bool rollover(helpers::Pool& p);

	protected:

		/**
		 Actual writing occurs here.
		*/
		void subAppend(const spi::LoggingEventPtr& event, helpers::Pool& p) override;

	protected:
		/**
		   Returns an OutputStreamWriter when passed an OutputStream.  The
		   encoding used will depend on the value of the
		   <code>encoding</code> property.  If the encoding value is
		   specified incorrectly the writer will be opened using the default
		   system encoding (an error message will be printed to the loglog.
		 @param os output stream, may not be null.
		 @return new writer.
		 */
		helpers::WriterPtr createWriter(helpers::OutputStreamPtr& os) override;

	private:
		/**
		 * Coordinate a rollover with other processes

		 * @return true if this process perfomed the rollover.
		 */
		bool synchronizedRollover(helpers::Pool& p, const TriggeringPolicyPtr& trigger = TriggeringPolicyPtr() );

		/**
		 * Set the length of current active log file to \c length bytes.
		 */
		void setFileLength(size_t length);

		/**
		 * Is it possible the current log file was renamed?
		 */
		bool isRolloverCheckNeeded();

		/**
		 *  Was \c fileName renamed?
		 *  @param pSize if not NULL, receives the log file size
		 * @return true if the log file must be reopened
		 */
		bool isAlreadyRolled(const LogString& fileName, size_t* pSize = 0);

		/**
		 * Put the current size of the log file into \c pSize.
		 * @return true if the log file size was put into \c pSize
		 */
		bool getCurrentFileSize(size_t* pSize);

		/**
		 * re-open \c fileName (used after it has been renamed)
		 */
		void reopenFile(const LogString& fileName);
};

LOG4CXX_PTR_DEF(MultiprocessRollingFileAppender);

}
}

#endif

