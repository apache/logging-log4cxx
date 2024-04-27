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

#ifndef _LOG4CXX_ASYNC_APPENDER_H
#define _LOG4CXX_ASYNC_APPENDER_H

#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/appenderattachableimpl.h>
#include <log4cxx/spi/loggingevent.h>

namespace LOG4CXX_NS
{
LOG4CXX_LIST_DEF(LoggingEventList, spi::LoggingEventPtr);

/**
The AsyncAppender decouples logging event creation from output
by processing log events asynchronously.

The AsyncAppender stores the logging event in a bounded buffer
and then returns control to the application.
A separate thread forwards events to the attached appender(s).
You can attach multiple appenders to an AsyncAppender.

The AsyncAppender is useful when outputting to a slow event sink,
for example, a remote SMTP server or a database.
Attaching a FileAppender to AsyncAppender is not recommended
as the inter-thread communication overhead
can exceed the time to write directly to a file.

When the application produces logging events faster
than the background thread is able to process,
the bounded buffer can become full.
In this situation AsyncAppender will either
block until the bounded buffer has a free slot or
discard the event.
The <b>Blocking</b> property controls which behaviour is used.
When events are discarded,
the logged output will indicate this
with a log message prefixed with <i>Discarded</i>.
The output may contain one <i>Discarded</i> message per logger name,
the logging event of the highest level for each logger
whose events have been discarded.

To determine whether the application produces logging events faster
than the background thread is able to process, enable [Log4cxx internal debugging](internal-debugging.html).
The AsyncAppender will output a histogram of queue length frequencies when closed.

<b>Important note:</b> The <code>AsyncAppender</code> can only
be script configured using the {@link xml::DOMConfigurator DOMConfigurator}.
*/
class LOG4CXX_EXPORT AsyncAppender :
	public virtual spi::AppenderAttachable,
	public virtual AppenderSkeleton
{
	protected:
		struct AsyncAppenderPriv;

	public:
		DECLARE_LOG4CXX_OBJECT(AsyncAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(AsyncAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		LOG4CXX_CAST_ENTRY(spi::AppenderAttachable)
		END_LOG4CXX_CAST_MAP()

		/**
		 * Create new instance.
		*/
		AsyncAppender();

		/**
		 *  Destructor.
		 */
		virtual ~AsyncAppender();

		/**
		 * Add appender.
		 *
		 * @param newAppender appender to add, may not be null.
		*/
		void addAppender(const AppenderPtr newAppender) override;

		void doAppend(const spi::LoggingEventPtr& event,
			helpers::Pool& pool1) override;

		void append(const spi::LoggingEventPtr& event, helpers::Pool& p) override;

		/**
		Close this <code>AsyncAppender</code> by interrupting the
		dispatcher thread which will process all pending events before
		exiting.
		*/
		void close() override;

		/**
		 * Get iterator over attached appenders.
		 * @return list of all attached appenders.
		*/
		AppenderList getAllAppenders() const override;

		/**
		 * Get appender by name.
		 *
		 * @param name name, may not be null.
		 * @return matching appender or null.
		*/
		AppenderPtr getAppender(const LogString& name) const override;

		/**
		 * Gets whether the location of the logging request call
		 * should be captured.
		 *
		 * @return the current value of the <b>LocationInfo</b> option.
		*/
		bool getLocationInfo() const;
		/**
		* Determines if specified appender is attached.
		* @param appender appender.
		* @return true if attached.
		*/
		bool isAttached(const AppenderPtr appender) const override;

		bool requiresLayout() const override;

		/**
		 * Removes and closes all attached appenders.
		*/
		void removeAllAppenders() override;

		/**
		 * Removes an appender.
		 * @param appender appender to remove.
		*/
		void removeAppender(const AppenderPtr appender) override;
		/**
		* Remove appender by name.
		* @param name name.
		*/
		void removeAppender(const LogString& name) override;

		/**
		* The <b>LocationInfo</b> attribute is provided for compatibility
		* with log4j and has no effect on the log output.
		* @param flag new value.
		*/
		void setLocationInfo(bool flag);

		/**
		* The <b>BufferSize</b> option takes a non-negative integer value.
		* This integer value determines the maximum size of the bounded
		* buffer.
		* */
		void setBufferSize(int size);

		/**
		 * Gets the current buffer size.
		 * @return the current value of the <b>BufferSize</b> option.
		*/
		int getBufferSize() const;

		/**
		 * Sets whether appender should wait if there is no
		 * space available in the event buffer or immediately return.
		 *
		 * @param value true if appender should wait until available space in buffer.
		 */
		void setBlocking(bool value);

		/**
		 * Gets whether appender should block calling thread when buffer is full.
		 * If false, messages will be counted by logger and a summary
		 * message appended after the contents of the buffer have been appended.
		 *
		 * @return true if calling thread will be blocked when buffer is full.
		 */
		bool getBlocking() const;


		/**
		\copybrief AppenderSkeleton::setOption()

		Supported options | Supported values | Default value
		-------------- | ---------------- | ---------------
		LocationInfo | True,False | False
		BufferSize | int  | 128
		Blocking | True,False | True

		\sa AppenderSkeleton::setOption()
		 */
		void setOption(const LogString& option, const LogString& value) override;


	private:
		AsyncAppender(const AsyncAppender&);
		AsyncAppender& operator=(const AsyncAppender&);

		/**
		 *  Dispatch routine.
		 */
		void dispatch();

}; // class AsyncAppender
LOG4CXX_PTR_DEF(AsyncAppender);
}  //  namespace log4cxx

#endif//  _LOG4CXX_ASYNC_APPENDER_H

