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
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/rolling/triggeringpolicy.h>
#include <log4cxx/rolling/rollingpolicy.h>
#include <log4cxx/rolling/action.h>

namespace LOG4CXX_NS
{
namespace rolling
{


/**
 * A special version of the RollingFileAppender that acts properly with multiple processes
 */
class LOG4CXX_EXPORT MultiprocessRollingFileAppender : public FileAppender
{
		DECLARE_LOG4CXX_OBJECT(MultiprocessRollingFileAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(MultiprocessRollingFileAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(FileAppender)
		END_LOG4CXX_CAST_MAP()
	protected:
		struct MultiprocessRollingFileAppenderPriv;

	public:
		MultiprocessRollingFileAppender();

		/**
		\copybrief FileAppender::activateOptions()

		Activate the attached TriggeringPolicy and RollingPolicy.

		\sa FileAppender::activateOptions()
		*/
		void activateOptions(helpers::Pool&) override;


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

		bool rolloverInternal(LOG4CXX_NS::helpers::Pool& p);

	public:

		RollingPolicyPtr getRollingPolicy() const;

		TriggeringPolicyPtr getTriggeringPolicy() const;

		/**
		 * Sets the rolling policy. In case the 'policy' argument also implements
		 * {@link TriggeringPolicy}, then the triggering policy for this appender
		 * is automatically set to be the policy argument.
		 * @param policy
		 */
		void setRollingPolicy(const RollingPolicyPtr& policy);

		void setTriggeringPolicy(const TriggeringPolicyPtr& policy);

	public:
		/**
		  * Close appender.  Waits for any asynchronous file compression actions to be completed.
		*/
		void close() override;

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

	public:
		/**
		 * Get byte length of current active log file.
		 * @return byte length of current active log file.
		 */
		size_t getFileLength() const;

		/**
		 * Increments estimated byte length of current active log file.
		 * @param increment additional bytes written to log file.
		 */
		void incrementFileLength(size_t increment);

	private:
		/**
		 * Set byte length of current active log file.
		 * @return void
		 */
		void setFileLength(size_t length);

		/**
		 *  Release the file lock
		 * @return void
		 */
		void releaseFileLock(apr_file_t* lock_file);
		/**
		 * re-open the latest file when its own handler has been renamed
		 * @return void
		 */
		void reopenLatestFile(LOG4CXX_NS::helpers::Pool& p);

		friend class CountingOutputStream;

};

LOG4CXX_PTR_DEF(MultiprocessRollingFileAppender);

}
}

#endif

