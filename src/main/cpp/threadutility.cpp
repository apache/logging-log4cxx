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

#include "log4cxx/helpers/threadutility.h"
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include "log4cxx/private/log4cxx_private.h"
#include "log4cxx/helpers/loglog.h"
#include "log4cxx/helpers/transcoder.h"

#include <atomic>
#include <signal.h>
#include <mutex>
#include <list>
#include <condition_variable>
#include <algorithm>

#ifdef _WIN32
	#include <windows.h>
	#include <processthreadsapi.h>
#endif

#if LOG4CXX_EVENTS_AT_EXIT
#include <log4cxx/private/atexitregistry.h>
#endif
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/helpers/aprinitializer.h>

namespace LOG4CXX_NS
{
namespace helpers
{

struct ThreadUtility::priv_data
{
	priv_data()
#if LOG4CXX_EVENTS_AT_EXIT
		: atExitRegistryRaii{ [this]{ stopThread(); } }
#endif
	{
	}

	~priv_data()
	{ stopThread(); }

	/**
	 * Configured behaviour, if user-provided functions have not been provided.
	 */
	ThreadConfigurationType config_type{ ThreadConfigurationType::BlockSignalsAndNameThread };
	/**
	 * A user-provided pre-start thread function.
	 */
	ThreadStartPre          start_pre{nullptr};
	/**
	 * A user-provided thread naming function.
	 */
	ThreadStarted           set_name{nullptr};
	/**
	 * A user-provided post-start thread function.
	 */
	ThreadStartPost         start_post{nullptr};

	using TimePoint = std::chrono::time_point<std::chrono::system_clock>;
	struct NamedPeriodicFunction
	{
		LogString             name;
		Period                delay;
		TimePoint             nextRun;
		std::function<void()> f;
		int                   errorCount;
		bool                  removed;
	};
	using JobStore = std::list<NamedPeriodicFunction>;
	JobStore                  jobs;
	std::recursive_mutex      job_mutex;
	std::thread               thread;
	std::condition_variable   interrupt;
	std::mutex                interrupt_mutex;
	bool                      wakeup{ false };
	std::atomic<bool>         terminated{ false };
	int                       retryCount{ 2 };
	Period                    maxDelay{ 0 };
	std::atomic<bool>         threadIsActive{ false };
	LoggerPtr                 log;

	void doPeriodicTasks();

	bool findRunnableTask(NamedPeriodicFunction *foundTask);

	void scheduleNextRun(const LogString& name, const Period& delay, bool success);

	void setTerminated()
	{
		std::lock_guard<std::recursive_mutex> lock(job_mutex);
		terminated.store(true);
	}
	
	void wakeThread()
	{
		std::unique_lock<std::mutex> lock(this->interrupt_mutex);
		this->wakeup = true;
		this->interrupt.notify_all();
	}

	void stopThread()
	{
		LOGLOG_DEBUG(log, "stopThread");
		setTerminated();
		wakeThread();
		if (thread.joinable())
			thread.join();
	}

#if LOG4CXX_EVENTS_AT_EXIT
	helpers::AtExitRegistry::Raii atExitRegistryRaii;
#endif
};

struct ThreadUtility::ThreadStartContext::Impl
{
	ThreadUtility::priv_data* parent;
	bool                      sigmask_valid{ false };
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	sigset_t                  old_mask;
#endif

	Impl(ThreadUtility::priv_data* pPriv) : parent(pPriv) {}

	/**
	 * A pre-start thread function that blocks signals to the new thread
	 * (if the system has pthreads).  If the system does not have pthreads,
	 * does nothing.
	 */
	void preThreadBlockSignals();

	/**
	 * A thread_started function that names the thread using the appropriate
	 * system call.
	 */
	void threadStartedNameThread
		( LogString                threadName
		, std::thread::id          thread_id
		, std::thread::native_handle_type native_handle
		);

	/**
	 * A post-start thread function that unblocks signals that preThreadBlockSignals
	 * blocked before starting the thread.  If the system does not have pthreads,
	 * does nothing.
	 */
	void postThreadUnblockSignals();
};

ThreadUtility::ThreadStartContext::ThreadStartContext(ThreadUtility* parent)
	: m_priv( std::make_unique<Impl>(parent->m_priv.get()) )
{
	if (auto user_provided_pre_start = m_priv->parent->start_pre)
		user_provided_pre_start();
	else if (m_priv->parent->config_type == ThreadConfigurationType::BlockSignalsOnly)
		m_priv->preThreadBlockSignals();
	else if (m_priv->parent->config_type == ThreadConfigurationType::BlockSignalsAndNameThread)
		m_priv->preThreadBlockSignals();
}

ThreadUtility::ThreadStartContext::~ThreadStartContext()
{
	if (auto user_provided_post_start = m_priv->parent->start_post)
		user_provided_post_start();
	else if (m_priv->parent->config_type == ThreadConfigurationType::BlockSignalsOnly)
		m_priv->postThreadUnblockSignals();
	else if (m_priv->parent->config_type == ThreadConfigurationType::BlockSignalsAndNameThread)
		m_priv->postThreadUnblockSignals();
}

void ThreadUtility::ThreadStartContext::setThreadName
	( LogString                       threadName
	, std::thread::id                 threadId
	, std::thread::native_handle_type nativeHandle
	) const
{
	if (auto user_provided_set_name = m_priv->parent->set_name)
		user_provided_set_name(threadName, threadId, nativeHandle);
	else if (m_priv->parent->config_type == ThreadConfigurationType::NameThreadOnly)
		m_priv->threadStartedNameThread(threadName, threadId, nativeHandle);
	else if (m_priv->parent->config_type == ThreadConfigurationType::BlockSignalsAndNameThread)
		m_priv->threadStartedNameThread(threadName, threadId, nativeHandle);
}

ThreadUtility::ThreadUtility()
	: m_priv( std::make_unique<priv_data>() )
{
}

ThreadUtility::~ThreadUtility() {}

auto ThreadUtility::instancePtr() -> ManagerPtr
{
	auto result = APRInitializer::getOrAddUnique<Manager>
		( []() -> ObjectPtr
			{ return std::make_shared<Manager>(); }
		);
	return result;
}

ThreadUtility* ThreadUtility::instance()
{
	return &instancePtr()->value();
}

ThreadConfigurationType ThreadUtility::configure( ThreadConfigurationType type )
{
	auto p = instance();
	auto result = p->m_priv->config_type;
	p->m_priv->start_pre = nullptr;
	p->m_priv->set_name = nullptr;
	p->m_priv->start_post = nullptr;
	p->m_priv->config_type = type;
	return result;
}

ThreadConfigurationType ThreadUtility::configureFuncs
	( ThreadStartPre  pre_start
	, ThreadStarted   set_name
	, ThreadStartPost post_start
	)
{
	m_priv->start_pre = pre_start;
	m_priv->set_name = set_name;
	m_priv->start_post = post_start;
	return m_priv->config_type;
}

void ThreadUtility::ThreadStartContext::Impl::preThreadBlockSignals()
{
#if LOG4CXX_HAS_PTHREAD_SIGMASK
	sigset_t set;
	sigfillset(&set);

	if ( pthread_sigmask(SIG_SETMASK, &set, &old_mask) < 0 )
	{
		LOGLOG_ERROR( LOG4CXX_STR("Unable to set thread sigmask") );
		sigmask_valid = false;
	}
	else
	{
		sigmask_valid = true;
	}

#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}

void ThreadUtility::ThreadStartContext::Impl::threadStartedNameThread
	( LogString                       threadName
	, std::thread::id                 threadId
	, std::thread::native_handle_type nativeHandle
	)
{
#if defined(_WIN32)
	typedef HRESULT (WINAPI *TSetThreadDescription)(HANDLE, PCWSTR);
	static struct initialiser
	{
		HMODULE hKernelBase;
		TSetThreadDescription SetThreadDescription;
		initialiser()
			: hKernelBase(GetModuleHandleA("KernelBase.dll"))
			, SetThreadDescription(nullptr)
		{
			if (hKernelBase)
				SetThreadDescription = reinterpret_cast<TSetThreadDescription>(GetProcAddress(hKernelBase, "SetThreadDescription"));
		}
	} win32Func;
	if (win32Func.SetThreadDescription)
	{
		LOG4CXX_ENCODE_WCHAR(wthreadName, threadName);
#if LOG4CXX_HAS_PTHREAD_GETHANDLE
		auto win_handle = static_cast<HANDLE>(pthread_gethandle(nativeHandle));
#else
		auto win_handle = static_cast<HANDLE>(nativeHandle);
#endif
		if(FAILED(win32Func.SetThreadDescription(win_handle, wthreadName.c_str())))
			LOGLOG_ERROR( LOG4CXX_STR("unable to set thread name") );
	}
#elif LOG4CXX_HAS_PTHREAD_SETNAME
	LOG4CXX_ENCODE_CHAR(sthreadName, threadName);
	if (pthread_setname_np(static_cast<pthread_t>(nativeHandle), sthreadName.c_str()) < 0) {
		LOGLOG_ERROR(LOG4CXX_STR("unable to set thread name"));
	}
#endif
}

void ThreadUtility::ThreadStartContext::Impl::postThreadUnblockSignals()
{
#if LOG4CXX_HAS_PTHREAD_SIGMASK

	// Only restore the signal mask if we were able to set it in the first place.
	if ( sigmask_valid )
	{
		if ( pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) < 0 )
		{
			LOGLOG_ERROR( LOG4CXX_STR("Unable to set thread sigmask") );
		}
	}

#endif /* LOG4CXX_HAS_PTHREAD_SIGMASK */
}

/**
 * Add a periodic task
 */
void ThreadUtility::addPeriodicTask(const LogString& name, std::function<void()> f, const Period& delay)
{
	if (!m_priv->log)
		m_priv->log = LogLog::getLogger(LOG4CXX_STR("ThreadUtility"));
	LOGLOG_DEBUG(m_priv->log, LOG4CXX_STR("addPeriodicTask: ") << name);
	std::lock_guard<std::recursive_mutex> lock(m_priv->job_mutex);
	if (m_priv->maxDelay < delay)
		m_priv->maxDelay = delay;
	auto currentTime = std::chrono::system_clock::now();
	m_priv->jobs.push_back( priv_data::NamedPeriodicFunction{name, delay, currentTime + delay, f, 0, false} );

	// Restart thread if it has stopped.
	if (!m_priv->threadIsActive.load() && m_priv->thread.joinable())
		m_priv->thread.join();

	if (!m_priv->thread.joinable())
	{
		m_priv->terminated.store(false);
		m_priv->threadIsActive.store(true);
		m_priv->thread = createThread(LOG4CXX_STR("log4cxx"), [this]()
			{
				LOGLOG_DEBUG(m_priv->log, "doPeriodicTasks: " << "started");
				m_priv->doPeriodicTasks();
				LOGLOG_DEBUG(m_priv->log, "doPeriodicTasks: " << "stopped");
				m_priv->threadIsActive.store(false);
			});
	}
	else
		m_priv->wakeThread();
}

/**
 * Is this currently running a background thread?
 */
bool ThreadUtility::isProcessingThreadActive() const
{
	return m_priv->threadIsActive.load();
}

/**
 * Is this already running a \c taskName periodic task?
 */
bool ThreadUtility::hasPeriodicTask(const LogString& name)
{
	std::lock_guard<std::recursive_mutex> lock(m_priv->job_mutex);
	auto pItem = std::find_if(m_priv->jobs.begin(), m_priv->jobs.end()
		, [&name](const priv_data::NamedPeriodicFunction& item)
		{ return !item.removed && name == item.name; }
		);
	return m_priv->jobs.end() != pItem;
}

/**
 * Remove all periodic tasks and stop the processing thread
 */
void ThreadUtility::removeAllPeriodicTasks()
{
	LOGLOG_DEBUG(m_priv->log, "removeAllPeriodicTasks");
	{
		std::lock_guard<std::recursive_mutex> lock(m_priv->job_mutex);
		while (!m_priv->jobs.empty())
			m_priv->jobs.pop_back();
	}
	m_priv->stopThread();
}

/**
 * Remove the \c taskName periodic task
 */
void ThreadUtility::removePeriodicTask(const LogString& name)
{
	std::lock_guard<std::recursive_mutex> lock(m_priv->job_mutex);
	auto pItem = std::find_if(m_priv->jobs.begin(), m_priv->jobs.end()
		, [&name](const priv_data::NamedPeriodicFunction& item)
		{ return !item.removed && name == item.name; }
		);
	if (m_priv->jobs.end() != pItem)
	{
		LOGLOG_DEBUG(m_priv->log, LOG4CXX_STR("removePeriodicTask: ") << name);
		pItem->removed = true;
		m_priv->wakeThread();
	}
}

/**
 * Remove any periodic task matching \c namePrefix
 */
void ThreadUtility::removePeriodicTasksMatching(const LogString& namePrefix)
{
	while (1)
	{
		std::lock_guard<std::recursive_mutex> lock(m_priv->job_mutex);
		auto pItem = std::find_if(m_priv->jobs.begin(), m_priv->jobs.end()
			, [&namePrefix](const priv_data::NamedPeriodicFunction& item)
			{ return !item.removed && namePrefix.size() <= item.name.size() && item.name.substr(0, namePrefix.size()) == namePrefix; }
			);
		if (m_priv->jobs.end() == pItem)
			break;
		pItem->removed = true;
	}
	m_priv->wakeThread();
}

// Run ready tasks
void ThreadUtility::priv_data::doPeriodicTasks()
{
	while (!this->terminated.load())
	{
		TimePoint nextOperationTime = std::chrono::system_clock::now() + this->maxDelay;

		// Run each due task with job_mutex released, so a long-running callback
		// (e.g. a reconnect blocked on network I/O) does not stall removePeriodicTask()
		while (!this->terminated.load())
		{
			NamedPeriodicFunction task;
			if (!this->findRunnableTask(&task)) // No tasks due?
				break;

			// Execute the callback outside any lock
			bool success = false;
			try
			{
				task.f();
				success = true;
			}
			catch (std::exception& ex)
			{
				LogLog::warn(task.name, ex);
			}
			catch (...)
			{
				LogLog::warn(task.name + LOG4CXX_STR(" threw an exception"));
			}

			this->scheduleNextRun(task.name, task.delay, success);
		}

		// Update nextOperationTime under the lock
		{
			std::lock_guard<std::recursive_mutex> lock(this->job_mutex);
			for (const auto& item : this->jobs)
			{
				if (!item.removed && item.nextRun < nextOperationTime)
				{
					nextOperationTime = item.nextRun;
				}
			}
		}

		// Delete removed and faulty tasks
		while (1)
		{
			std::lock_guard<std::recursive_mutex> lock(this->job_mutex);
			auto pItem = std::find_if(this->jobs.begin(), this->jobs.end()
				, [this](const NamedPeriodicFunction& item)
				{ return item.removed || this->retryCount < item.errorCount; }
				);
			if (this->jobs.end() == pItem)
				break;
			LOGLOG_DEBUG(this->log, LOG4CXX_STR("doPeriodicTasks: erase ") << pItem->name);
			this->jobs.erase(pItem);
			if (this->jobs.empty())
				return;
		}

		// Wait until the next task is due or an add/remove/shutdown wakes us
		std::unique_lock<std::mutex> lock(this->interrupt_mutex);
		this->interrupt.wait_until(lock, nextOperationTime
			, [this]{ return this->wakeup; }
			);
		this->wakeup = false;
	}
}

bool ThreadUtility::priv_data::findRunnableTask(NamedPeriodicFunction *foundTask)
{
	std::lock_guard<std::recursive_mutex> lock(this->job_mutex);
	bool result = false;
	auto currentTime = std::chrono::system_clock::now();
	auto pItem = std::find_if(this->jobs.begin(), this->jobs.end()
		, [currentTime](const NamedPeriodicFunction& item)
		{ return !item.removed && item.nextRun <= currentTime; }
		);
	if (pItem != this->jobs.end())
	{
		if (foundTask)
			*foundTask = *pItem;
		result = true;
	}
	return result;
}

void ThreadUtility::priv_data::scheduleNextRun(const LogString& name, const Period& delay, bool success)
{
	std::lock_guard<std::recursive_mutex> lock(this->job_mutex);
	auto pItem = std::find_if(this->jobs.begin(), this->jobs.end()
		, [&name](const NamedPeriodicFunction& item)
		{ return !item.removed && name == item.name; }
		);

	if (pItem != this->jobs.end())
	{
		// Always push nextRun out, so a failing task waits before the next retry
		pItem->nextRun = std::chrono::system_clock::now() + delay;
		if (success)
			pItem->errorCount = 0;
		else
			++pItem->errorCount;
	}
}

} //namespace helpers
} //namespace log4cxx
