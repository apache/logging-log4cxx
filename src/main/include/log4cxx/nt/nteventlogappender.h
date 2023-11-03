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

#ifndef _LOG4CXX_NT_EVENT_LOG_APPENDER_HEADER_
#define _LOG4CXX_NT_EVENT_LOG_APPENDER_HEADER_

#include <log4cxx/appenderskeleton.h>

namespace LOG4CXX_NS
{
namespace nt
{
/**
 * Appends log events to NT EventLog.
 */
class LOG4CXX_EXPORT NTEventLogAppender : public AppenderSkeleton
{
	public:
		DECLARE_LOG4CXX_OBJECT(NTEventLogAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(NTEventLogAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		NTEventLogAppender();
		NTEventLogAppender(const LogString& server, const LogString& log,
			const LogString& source, const LayoutPtr& layout);

		virtual ~NTEventLogAppender();

		/**
		\copybrief AppenderSkeleton::activateOptions()

		Calls <a href="https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew">RegisterEventSource</a>.
		*/
		void activateOptions(helpers::Pool& p) override;
		void close() override;

		/**
		\copybrief AppenderSkeleton::setOption()

		Supported options | Supported values | Default value
		-------------- | ---------------- | ---------------
		Server | (\ref winapi "1") | NULL
		Source | (\ref winapi "1") | -
		Log | (\ref eventLog "2") | Application

		\anchor winapi (1) Passed to the Win32 API method <a href="https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew">RegisterEventSource</a>.

		\anchor eventLog (2) An event log name.

		\sa AppenderSkeleton::setOption()
		*/
		void setOption(const LogString& option, const LogString& value) override;

		/**
		 * The SocketAppender does not use a layout. Hence, this method
		 * returns <code>false</code>.
		 *
		 */
		bool requiresLayout() const override
		{
			return true;
		}

		void setSource(const LogString& source);

		const LogString& getSource() const;

		void setLog(const LogString& log);

		const LogString& getLog() const;

		void setServer(const LogString& server);

		const LogString& getServer() const;


	protected:
		//
		//   these typedef are proxies for the real Win32 definitions
		//     and need to be cast to the global definitions before
		//     use with a Win32 API call
		typedef void SID;
		typedef void* HANDLE;

		void append(const spi::LoggingEventPtr& event, helpers::Pool& p) override;
		static unsigned short getEventType(const spi::LoggingEventPtr& event);
		static unsigned short getEventCategory(const spi::LoggingEventPtr& event);
		/*
		 * Add this source with appropriate configuration keys to the registry.
		 */
		void addRegistryInfo();

		struct NTEventLogAppenderPrivate;
		static LogString getErrorString(const LogString& function);

	private:
		NTEventLogAppender(const NTEventLogAppender&);
		NTEventLogAppender& operator=(const NTEventLogAppender&);
}; // class NTEventLogAppender

LOG4CXX_PTR_DEF(NTEventLogAppender);

}  // namespace nt
} // namespace log4cxx

#endif //_LOG4CXX_NT_EVENT_LOG_APPENDER_HEADER_
