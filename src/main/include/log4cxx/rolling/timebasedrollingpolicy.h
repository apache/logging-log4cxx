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


#if !defined(_LOG4CXX_ROLLING_TIME_BASED_ROLLING_POLICY_H)
#define _LOG4CXX_ROLLING_TIME_BASED_ROLLING_POLICY_H

#include <log4cxx/rolling/rollingpolicybase.h>
#include <log4cxx/rolling/triggeringpolicy.h>
#include <log4cxx/writerappender.h>
#include <log4cxx/helpers/outputstream.h>
#include <functional>

namespace LOG4CXX_NS
{

namespace rolling
{



/**
 * <code>TimeBasedRollingPolicy</code> is both easy to configure and quite
 * powerful.
 *
 * <p>In order to use  <code>TimeBasedRollingPolicy</code>, the
 * <b>FileNamePattern</b> option must be set. It basically specifies the name of the
 * rolled log files. The value <code>FileNamePattern</code> should consist of
 * the name of the file, plus a suitably placed <code>%d</code> conversion
 * specifier. The <code>%d</code> conversion specifier may contain a date and
 * time pattern as specified by the {@link log4cxx::helpers::SimpleDateFormat} class. If
 * the date and time pattern is ommitted, then the default pattern of
 * "yyyy-MM-dd" is assumed. The following examples should clarify the point.
 *
 * <p>
 * <table cellspacing="5px" border="1">
 *   <tr>
 *     <th><code>FileNamePattern</code> value</th>
 *     <th>Rollover schedule</th>
 *     <th>Example</th>
 *   </tr>
 *   <tr>
 *     <td nowrap="true"><code>/wombat/folder/foo.%d</code></td>
 *     <td>Daily rollover (at midnight).  Due to the omission of the optional
 *         time and date pattern for the %d token specifier, the default pattern
 *         of "yyyy-MM-dd" is assumed, which corresponds to daily rollover.
 *     </td>
 *     <td>During November 23rd, 2004, logging output will go to
 *       the file <code>/wombat/foo.2004-11-23</code>. At midnight and for
 *       the rest of the 24th, logging output will be directed to
 *       <code>/wombat/foo.2004-11-24</code>.
 *     </td>
 *   </tr>
 *   <tr>
 *     <td nowrap="true"><code>/wombat/foo.%d{yyyy-MM}.log</code></td>
 *     <td>Rollover at the beginning of each month.</td>
 *     <td>During the month of October 2004, logging output will go to
 *     <code>/wombat/foo.2004-10.log</code>. After midnight of October 31st
 *     and for the rest of November, logging output will be directed to
 *       <code>/wombat/foo.2004-11.log</code>.
 *     </td>
 *   </tr>
 * </table>
 * <h2>Automatic file compression</h2>
 * <code>TimeBasedRollingPolicy</code> supports automatic file compression.
 * This feature is enabled if the value of the <b>FileNamePattern</b> option
 * ends with <code>.gz</code> or <code>.zip</code>.
 * <p>
 * <table cellspacing="5px" border="1">
 *   <tr>
 *     <th><code>FileNamePattern</code> value</th>
 *     <th>Rollover schedule</th>
 *     <th>Example</th>
 *   </tr>
 *   <tr>
 *     <td nowrap="true"><code>/wombat/foo.%d.gz</code></td>
 *     <td>Daily rollover (at midnight) with automatic GZIP compression of the
 *      arcived files.</td>
 *     <td>During November 23rd, 2004, logging output will go to
 *       the file <code>/wombat/foo.2004-11-23</code>. However, at midnight that
 *       file will be compressed to become <code>/wombat/foo.2004-11-23.gz</code>.
 *       For the 24th of November, logging output will be directed to
 *       <code>/wombat/folder/foo.2004-11-24</code> until its rolled over at the
 *       beginning of the next day.
 *     </td>
 *   </tr>
 * </table>
 *
 * <h2>Decoupling the location of the active log file and the archived log files</h2>
 * <p>The <em>active file</em> is defined as the log file for the current period
 * whereas <em>archived files</em> are thos files which have been rolled over
 * in previous periods.
 *
 * <p>By setting the <b>ActiveFileName</b> option you can decouple the location
 * of the active log file and the location of the archived log files.
 * <p>
 *  <table cellspacing="5px" border="1">
 *   <tr>
 *     <th><code>FileNamePattern</code> value</th>
 *     <th>ActiveFileName</th>
 *     <th>Rollover schedule</th>
 *     <th>Example</th>
 *   </tr>
 *   <tr>
 *     <td nowrap="true"><code>/wombat/foo.log.%d</code></td>
 *     <td nowrap="true"><code>/wombat/foo.log</code></td>
 *     <td>Daily rollover.</td>
 *
 *     <td>During November 23rd, 2004, logging output will go to
 *       the file <code>/wombat/foo.log</code>. However, at midnight that file
 *       will archived as <code>/wombat/foo.log.2004-11-23</code>. For the 24th
 *       of November, logging output will be directed to
 *       <code>/wombat/folder/foo.log</code> until its archived as
 *       <code>/wombat/foo.log.2004-11-24</code> at the beginning of the next
 *       day.
 *     </td>
 *   </tr>
 * </table>
 * <p>
 * If configuring programatically, do not forget to call {@link #activateOptions}
 * method before using this policy. Moreover, {@link #activateOptions} of
 * <code> TimeBasedRollingPolicy</code> must be called <em>before</em> calling
 * the {@link #activateOptions} method of the owning
 * <code>RollingFileAppender</code>.
 */
class LOG4CXX_EXPORT TimeBasedRollingPolicy : public virtual RollingPolicyBase,
	public virtual TriggeringPolicy
{
		DECLARE_LOG4CXX_OBJECT(TimeBasedRollingPolicy)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(TimeBasedRollingPolicy)
		LOG4CXX_CAST_ENTRY_CHAIN(RollingPolicyBase)
		LOG4CXX_CAST_ENTRY_CHAIN(TriggeringPolicy)
		END_LOG4CXX_CAST_MAP()

	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(TimeBasedRollingPolicyPrivate, m_priv)

	public:
		TimeBasedRollingPolicy();
		virtual ~TimeBasedRollingPolicy();

		/**
		\copybrief RollingPolicyBase::activateOptions()

		Logs a warning if an option is not valid.

		\sa RollingPolicyBase::activateOptions()
		*/
		void activateOptions(helpers::Pool& ) override;

		void setMultiprocess(bool multiprocess);

		/**
		 * {@inheritDoc}
		 */
		RolloverDescriptionPtr initialize(
			const   LogString&              currentActiveFile,
			const   bool                    append,
			helpers::Pool& pool) override;

		/**
		 * {@inheritDoc}
		 */
		RolloverDescriptionPtr rollover(
			const   LogString&              currentActiveFile,
			const   bool                    append,
			helpers::Pool& pool) override;

		/**
		 * Determines if a rollover may be appropriate at this time.  If
		 * true is returned, RolloverPolicy.rollover will be called but it
		 * can determine that a rollover is not warranted.
		 *
		 * @param appender A reference to the appender.
		 * @param event A reference to the currently event.
		 * @param filename The filename for the currently active log file.
		 * @param fileLength Length of the file in bytes.
		 * @return true if a rollover should occur.
		 */
		bool isTriggeringEvent(
			Appender* appender,
			const spi::LoggingEventPtr& event,
			const LogString& filename,
			size_t fileLength) override;

		/**
		\copybrief RollingPolicyBase::setOption()

		Supported options | Supported values | Default value
		:-------------- | :----------------: | :---------------:
		ThrowIOExceptionOnForkFailure | True,False | True

		\sa RollingPolicyBase::setOption()
		 */
		void setOption(const LogString& option, const LogString& value) override;

	protected:
		/**
		 * A map from "d" and "date" to a date conversion formatter.
		 *
		 * \sa FileDatePatternConverter
		 */
		LOG4CXX_NS::pattern::PatternMap getFormatSpecifiers() const override;

	private:

		/**
		 * Generate mmap file
		 */
		int createMMapFile(const std::string& lastfilename, LOG4CXX_NS::helpers::Pool& pool);

		/**
		 *  Detect if the mmap file is empty
		 */
		bool isMapFileEmpty(LOG4CXX_NS::helpers::Pool& pool);

		/**
		 *   init MMapFile
		 */
		void initMMapFile(const LogString& lastFileName, LOG4CXX_NS::helpers::Pool& pool);

		/**
		 *   lock MMapFile
		 */
		int lockMMapFile(int type);

		/**
		 *   unlock MMapFile
		 */
		int unLockMMapFile();

		/**
		 *   create MMapFile/lockFile
		 */
		const std::string createFile(const std::string& filename, const std::string& suffix, LOG4CXX_NS::helpers::Pool& pool);

};

LOG4CXX_PTR_DEF(TimeBasedRollingPolicy);

}
}

#endif

