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

#if !defined(_LOG4CXX_ROLLING_ROLLING_POLICY_H)
#define _LOG4CXX_ROLLING_ROLLING_POLICY_H

#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/rolling/rolloverdescription.h>
#include <log4cxx/file.h>

namespace LOG4CXX_NS
{
namespace rolling
{


/**
 * A <code>RollingPolicy</code> is responsible for performing the
 * rolling over of the active log file. The <code>RollingPolicy</code>
 * is also responsible for providing the <em>active log file</em>,
 * that is the live file where logging output will be directed.
 *
 *
 *
 *
*/
class LOG4CXX_EXPORT RollingPolicy :
	public virtual spi::OptionHandler
{
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(RollingPolicy)

	public:
		virtual ~RollingPolicy() {}

		/**
		 * Initialize the policy and return any initial actions for rolling file appender.
		 *
		 * @param currentActiveFile current value of RollingFileAppender.getFile().
		 * @param append current value of RollingFileAppender.getAppend().
		 * @return Description of the initialization, may be null to indicate
		 * no initialization needed.
		 */
#if LOG4CXX_ABI_VERSION <= 15
		RolloverDescriptionPtr initialize(const LogString& currentActiveFile, bool append);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to initialize() without a helpers::Pool parameter.
		*/
		virtual RolloverDescriptionPtr initialize(
			const   LogString&              currentActiveFile,
			const   bool                    append,
			LOG4CXX_NS::helpers::Pool& pool) = 0;
#define LOG4CXX_ROLLING_POLICY_INITIALIZE_FORMAL_PARAMETERS const LogString& currentActiveFile, bool append, helpers::Pool& p
#else
		virtual RolloverDescriptionPtr initialize(const LogString& currentActiveFile, bool append) = 0;
#define LOG4CXX_ROLLING_POLICY_INITIALIZE_FORMAL_PARAMETERS const LogString& currentActiveFile, bool append
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use initialize() without a Pool parameter instead")]]
		RolloverDescriptionPtr initialize(const LogString& currentActiveFile, bool append, helpers::Pool& pool);
#endif

		/**
		 * Prepare for a rollover.  This method is called prior to
		 * closing the active log file, performs any necessary
		 * preliminary actions and describes actions needed
		 * after close of current log file.
		 *
		 * @param currentActiveFile file name for current active log file.
		 * @param append current value of the parent FileAppender.getAppend().
		 * @return Description of pending rollover, may be null to indicate no rollover
		 * at this time.
		 */
#if LOG4CXX_ABI_VERSION <= 15
		RolloverDescriptionPtr rollover(const LogString& currentActiveFile, bool append);
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to rollover() without a helpers::Pool parameter.
		*/
		virtual RolloverDescriptionPtr rollover(
			const   LogString&              currentActiveFile,
			const   bool                    append,
			LOG4CXX_NS::helpers::Pool& pool) = 0;
#define LOG4CXX_ROLLING_POLICY_ROLLOVER_FORMAL_PARAMETERS const LogString& currentActiveFile, bool append, helpers::Pool& p
#else
		virtual RolloverDescriptionPtr rollover(const LogString& currentActiveFile, bool append) = 0;
#define LOG4CXX_ROLLING_POLICY_ROLLOVER_FORMAL_PARAMETERS const LogString& currentActiveFile, bool append
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use rollover() without a Pool parameter instead")]]
		RolloverDescriptionPtr rollover(const LogString& currentActiveFile, bool append, helpers::Pool& pool);
#endif
};

LOG4CXX_PTR_DEF(RollingPolicy);

}
}
#endif

