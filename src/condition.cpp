/***************************************************************************
                          condition.cpp  -  class Condition
                             -------------------
    begin                : 2003/09/29
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/helpers/condition.h>

#ifdef HAVE_MS_THREAD
#define _WIN32_WINNT 0x0400 // SignalObjectAndWait
#ifdef HAVE_MS_THREAD
#include <windows.h>
#endif
#endif

using namespace log4cxx::helpers;
using namespace log4cxx;

Condition::Condition()
{
#ifdef HAVE_PTHREAD
	::pthread_cond_init(&condition, 0);
#elif defined(HAVE_MS_THREAD)
	waiters = 0;
	wasBroadCast = false;
	waitersDone = ::CreateEvent(0, FALSE, FALSE, NULL);
#endif
}

Condition::~Condition()
{
#ifdef HAVE_PTHREAD
	::pthread_cond_destroy(&condition);
#elif defined(HAVE_MS_THREAD)
	::CloseHandle(waitersDone);
#endif
}

void Condition::broadcast()
{
#ifdef HAVE_PTHREAD
	::pthread_cond_broadcast(&condition);
#elif defined(HAVE_MS_THREAD)
#endif
}

void Condition::signal()
{
#ifdef HAVE_PTHREAD
	::pthread_cond_signal(&condition);
#elif defined(HAVE_MS_THREAD)
	// If there aren't any waiters, then this is a no-op.  Note that
	// this function *must* be called with the <external_mutex> held
	// since other wise there is a race condition that can lead to the
	// lost wakeup bug...  This is needed to ensure that the <waiters>
	// value is not in an inconsistent internal state while being
	// updated by another thread.

	// if (waiters != 0) (atomic comparison)
#	if _MSC_VER == 1200	// MSDEV 6
	if ((long)InterlockedCompareExchange((void**)&waiters, 0, 0) != 0)
#	else
	if ((long)InterlockedCompareExchange(&waiters, 0, 0) != 0)
#	endif
	{
		sema.post();
	}
#endif
}

void Condition::wait(Mutex& mutex)
{
#ifdef HAVE_PTHREAD
	::pthread_cond_wait(&condition, &mutex.mutex);
#elif defined(HAVE_MS_THREAD)

#if _MSC_VER == 1200	// MSDEV 6
	::InterlockedIncrement((long *)&waiters);
#else
	::InterlockedIncrement(&waiters);
#endif

    if (SignalObjectAndWait(mutex.mutex, sema.semaphore, INFINITE, FALSE)
		== WAIT_ABANDONED)
	{
		throw ConditionException();
	}

#if _MSC_VER == 1200	// MSDEV 6
	long oldWaiters = ::InterlockedDecrement((long*)&waiters);
#else
	long oldWaiters = ::InterlockedDecrement(&waiters);
#endif

	bool lastWaiter = wasBroadCast && (oldWaiters == 0);

	if (lastWaiter)
	{
		// This call atomically signals the <waiters_done_> event and
		// waits until it can acquire the mutex.  This is important to
		// prevent unfairness.
		if (SignalObjectAndWait(waitersDone, mutex.mutex, INFINITE, FALSE)
			== WAIT_ABANDONED)
		{
			throw ConditionException();
		}
	}

	mutex.lock();
#endif
}

void Condition::wait(Mutex& mutex, long timeOut)
{
}
