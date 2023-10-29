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

#if !defined(_LOG4CXX_ROLLING_SIZE_BASED_TRIGGERING_POLICY_H)
#define _LOG4CXX_ROLLING_SIZE_BASED_TRIGGERING_POLICY_H

#include <log4cxx/rolling/triggeringpolicy.h>

namespace LOG4CXX_NS
{

class File;

namespace helpers
{
class Pool;
}

namespace rolling
{

/**
 * SizeBasedTriggeringPolicy looks at size of the file being
 * currently written to.
 *
 *
 *
 */
class LOG4CXX_EXPORT SizeBasedTriggeringPolicy : public TriggeringPolicy
{
		DECLARE_LOG4CXX_OBJECT(SizeBasedTriggeringPolicy)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(SizeBasedTriggeringPolicy)
		LOG4CXX_CAST_ENTRY_CHAIN(TriggeringPolicy)
		END_LOG4CXX_CAST_MAP()

	protected:
		size_t maxFileSize;

	public:
		SizeBasedTriggeringPolicy();
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

		size_t getMaxFileSize();

		void setMaxFileSize(size_t l);

		/**
		\copybrief spi::OptionHandler::activateOptions()

		No action is performed in this implementation.
		*/
		void activateOptions(helpers::Pool&) override;

		/**
		\copybrief spi::OptionHandler::setOption()

		Supported options | Supported values | Default value
		-------------- | ---------------- | ---------------
		MaxFileSize | (\ref fileSize "1") | 10 MB

		\anchor fileSize (1) An integer in the range 0 - 2^63.
		 You can specify the value with the suffixes "KB", "MB" or "GB" so that the integer is
		 interpreted being expressed respectively in kilobytes, megabytes
		 or gigabytes. For example, the value "10KB" will be interpreted as 10240.
		*/
		void setOption(const LogString& option, const LogString& value) override;
};

LOG4CXX_PTR_DEF(SizeBasedTriggeringPolicy);

}
}
#endif

