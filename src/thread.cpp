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

#include <log4cxx/portability.h>

#if defined(LOG4CXX_HAVE_MS_THREAD)
#include <windows.h>
#endif

#include <log4cxx/helpers/thread.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(Runnable)
IMPLEMENT_LOG4CXX_OBJECT(Thread)

struct Thread::Impl
{
	Impl(): thread(0) {};

	/** Thread descriptor */
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_t thread;
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	void * thread;
#endif
private:
        Impl(const Impl&);
        Impl& operator=(const Impl&);
};

#ifdef LOG4CXX_HAVE_PTHREAD
#include <pthread.h>
#include <unistd.h> // usleep
void * threadProc(void * arg)
{
//	LogLog::debug(_T("entering thread proc"));
	Thread * thread = (Thread *)arg;
	thread->run();
	thread->releaseRef();
	pthread_exit(0);
	return 0;
}
#elif defined(LOG4CXX_HAVE_MS_THREAD)
DWORD WINAPI threadProc(void * arg)
{
//	LogLog::debug(_T("entering thread proc"));
	Thread * thread = (Thread *)arg;
	thread->run();
	thread->releaseRef();
	return 0;
}
#else
#include <unistd.h> // usleep
#endif


Thread::Thread(): impl( new Impl ), runnable(), parentMDCMap()
{
	addRef();
}

Thread::Thread(RunnablePtr runnable) :
     runnable(runnable),
     impl( new Impl ),
     parentMDCMap()
{
	addRef();
}

Thread::~Thread()
{
	// TODO: why don't we use Thread::join ?
	if (impl->thread != 0)
	{
#ifdef LOG4CXX_HAVE_PTHREAD
		::pthread_join(impl->thread, 0);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
		::CloseHandle((HANDLE)impl->thread);
#endif
		LOGLOG_DEBUG(_T("Thread destroyed."));
	}
}

unsigned long Thread::getCurrentThreadId()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	return (unsigned long)::pthread_self();
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	return ::GetCurrentThreadId();
#endif
}

void Thread::start()
{
	parentMDCMap = MDC::getContext();
#ifdef LOG4CXX_HAVE_PTHREAD
//	LogLog::debug(_T("Thread::start"));
	if (::pthread_create(&impl->thread, NULL, threadProc, this) != 0)
	{
		throw ThreadException();
	}
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	unsigned long threadId = 0;
	impl->thread =
		(void *)::CreateThread(NULL, 0, threadProc, this, 0, &threadId);
	if (impl->thread == 0)
	{
		throw ThreadException();
	}
#endif
}

void Thread::run()
{
	MDC::setContext(parentMDCMap);
	if (runnable != 0)
	{
		runnable->run();
	}
}

void Thread::join()
{
	bool bSuccess = true;
#ifdef LOG4CXX_HAVE_PTHREAD
	::pthread_join(impl->thread, 0);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	if (::WaitForSingleObject((HANDLE)impl->thread, INFINITE) != WAIT_OBJECT_0)
	{
		bSuccess = false;
	}

	::CloseHandle((HANDLE)impl->thread);
#endif

	impl->thread = 0;

	if (!bSuccess)
	{
		throw InterruptedException();
	}

	LOGLOG_DEBUG(_T("Thread ended."));
}

void Thread::setPriority(int newPriority)
{
	switch(newPriority)
	{
	case MIN_PRIORITY:
		break;
	case NORM_PRIORITY:
		break;
	case MAX_PRIORITY:
		break;
	}
}
