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

#ifndef _LOG4CXX_THREADUTILITY_H
#define _LOG4CXX_THREADUTILITY_H

#include <thread>
#include <functional>
#include <memory>
#include <chrono>

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/singletonholder.h>

namespace LOG4CXX_NS
{
namespace helpers
{

/**
 * A function that will be called before a thread is started.  This can
 * be used to (for example) block all of the signals in the thread, so
 * that when the thread is created it will have a correct signal mask.
*/
using ThreadStartPre = std::function<void()>;

/**
 * Called when a new thread has started.  This can be used to set
 * parameters for the thread in a platform-specific manner.
 *
 * @param threadName The name of the thread
 * @param threadId The ID of the thread as reported by std::thread::get_id
 * @param nativeHandle The native handle of the thread, as reported by
 * std::thread::native_handle
 */
using ThreadStarted = std::function
	< void
		( LogString                       threadName
		, std::thread::id                 threadId
		, std::thread::native_handle_type nativeHandle
		)
	>;

/**
 * Called after a thread has started. This can be used to (for example)
 * unblock the signals in the thread.
 */
using ThreadStartPost = std::function<void()>;

enum class ThreadConfigurationType
{
	NoConfiguration,
	BlockSignalsOnly,
	NameThreadOnly,
	BlockSignalsAndNameThread,
};

class LOG4CXX_EXPORT ThreadUtility
{
	private:
		friend class SingletonHolder<ThreadUtility>;
		ThreadUtility();

		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(priv_data, m_priv)
	public:
		~ThreadUtility();

		static ThreadUtility* instance();

		/**
		 * Use \c new_value as the behviour when starting a thread.
		 * Call-back function pointers are reset to nullptr.
		 */
		static void configure( ThreadConfigurationType new_value );

		/**
		 * Set call-back functions to use when starting a thread.
		 * Note that setting any of these parameters to nullptr is valid,
		 * and simply results in the callback not being called.
		 * @returns The previous configuration
		 */
		ThreadConfigurationType configureFuncs
			( ThreadStartPre  pre_start
			, ThreadStarted   set_name
			, ThreadStartPost post_start
			);

		/**
		 * Start a thread
		 */
		template<class Function, class... Args>
		std::thread createThread
			( LogString name
			, Function&& f
			, Args&& ... args
			)
		{
			ThreadStartContext ctx(this);
			std::thread t( f, args... );
			ctx.setThreadName(name, t.get_id(), t.native_handle());
			return t;
		}

		using Period = std::chrono::milliseconds;

		/**
		 * Add the \c taskName periodic task
		 */
		void addPeriodicTask(const LogString& taskName, std::function<void()> f, const Period& delay);

		/**
		 * Has a \c taskName periodic task already been added?
		 */
		bool hasPeriodicTask(const LogString& taskName);

		/**
		 * Is the processing thread running?
		 */
		bool isProcessingThreadActive() const;

		/**
		 * Remove all periodic tasks and stop the processing thread
		 */
		void removeAllPeriodicTasks();

		/**
		 * Remove the \c taskName periodic task
		 */
		void removePeriodicTask(const LogString& taskName);

		/**
		 * Remove any periodic task matching \c namePrefix
		 */
		void removePeriodicTasksMatching(const LogString& namePrefix);

		using Manager = SingletonHolder<ThreadUtility>;
		LOG4CXX_PTR_DEF(Manager);

		static ManagerPtr instancePtr();

private:
		struct LOG4CXX_EXPORT ThreadStartContext
		{
			LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(Impl, m_priv)
			ThreadStartContext(ThreadUtility* parent);
			~ThreadStartContext();
			void setThreadName
				( LogString                       threadName
				, std::thread::id                 threadId
				, std::thread::native_handle_type nativeHandle
				) const;
		};
};

} /* namespace helpers */
} /* namespace log4cxx */

#endif
