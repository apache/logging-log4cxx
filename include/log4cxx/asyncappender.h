/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
#include <deque>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/thread.h>
#include <log4cxx/helpers/mutex.h>
#include <log4cxx/helpers/condition.h>

struct apr_pool_t;

namespace log4cxx
{
	class AsyncAppender;
	typedef helpers::ObjectPtrT<AsyncAppender> AsyncAppenderPtr;

	/**
	The AsyncAppender lets users log events asynchronously. It uses a
	bounded buffer to store logging events.

	<p>The AsyncAppender will collect the events sent to it and then
	dispatch them to all the appenders that are attached to it. You can
	attach multiple appenders to an AsyncAppender.

	<p>The AsyncAppender uses a separate thread to serve the events in
	its bounded buffer.

	<p><b>Important note:</b> The <code>AsyncAppender</code> can only
	be script configured using the {@link xml::DOMConfigurator DOMConfigurator}.
	*/
	class LOG4CXX_EXPORT AsyncAppender :
		public virtual spi::AppenderAttachable,
		public virtual AppenderSkeleton
	{
	public:
		DECLARE_LOG4CXX_OBJECT(AsyncAppender)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(AsyncAppender)
			LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
			LOG4CXX_CAST_ENTRY(spi::AppenderAttachable)
		END_LOG4CXX_CAST_MAP()

        AsyncAppender();
		virtual ~AsyncAppender();

		void addAppender(const AppenderPtr& newAppender);

		void append(const spi::LoggingEventPtr& event);

		/**
		Close this <code>AsyncAppender</code> by interrupting the
		dispatcher thread which will process all pending events before
		exiting.
		*/
		void close();

		AppenderList getAllAppenders() const;
		AppenderPtr getAppender(const String& name) const;

		/**
		Returns the current value of the <b>LocationInfo</b> option.
		*/
		inline bool getLocationInfo() const
			{ return locationInfo; }

		/**
		Is the appender passed as parameter attached to this asyncappender?
		*/
		bool isAttached(const AppenderPtr& appender) const;

		void removeAllAppenders();
		void removeAppender(const AppenderPtr& appender);
		void removeAppender(const String& name);

		/**
		The <code>AsyncAppender</code> does not require a layout. Hence,
		this method always returns <code>false</code>.
		*/
		virtual bool requiresLayout() const
			{ return false; }

		/**
		* The <b>LocationInfo</b> attribute is provided for compatibility
		* with log4j and has no effect.
		* */
		inline void setLocationInfo(bool flag) {
			locationInfo = flag;
		}

		/**
		* The <b>BufferSize</b> option takes a non-negative integer value.
		* This integer value determines the maximum size of the bounded
		* buffer.
		* */
		void setBufferSize(int size);

		/**
		Returns the current value of the <b>BufferSize</b> option.
		*/
		int getBufferSize() const;

	private:
		std::deque<log4cxx::spi::LoggingEventPtr> queue;
		int size;
		//
		//   Condition is signaled when there is room available on the queue
		//
		log4cxx::helpers::Condition available;
		//
		//   Condition is signaled when there is at least one event in the queue.
		//
		log4cxx::helpers::Condition pending;
		
		helpers::Thread thread;

		bool locationInfo;
		helpers::AppenderAttachableImplPtr aai;

		enum { DEFAULT_BUFFER_SIZE = 128 };

		static void* LOG4CXX_THREAD_FUNC dispatch(apr_thread_t* thread, void* data);

	}; // class AsyncAppender

}  //  namespace log4cxx

#endif//  _LOG4CXX_ASYNC_APPENDER_H

