/***************************************************************************
                          thread.cpp  -  description
                             -------------------
    begin                : jeu mai 8 2003
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

#include <log4cxx/helpers/thread.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(Runnable)
IMPLEMENT_LOG4CXX_OBJECT(Thread)

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#include <unistd.h> // usleep
void * threadProc(void * arg)
{
//	LogLog::debug(_T("entering thread proc"));
	Thread * thread = (Thread *)arg;
	thread->run();
	delete thread;
	pthread_exit(0);
}
#elif defined(WIN32)
#include <windows.h>
DWORD WINAPI threadProc(void * arg)
{
//	LogLog::debug(_T("entering thread proc"));
	Thread * thread = (Thread *)arg;
	thread->run();
	delete thread;
	return 0;
}
#else
#include <unistd.h> // usleep
#endif


Thread::Thread() : thread(0)
{
}

Thread::Thread(RunnablePtr runnable) : thread(0), runnable(runnable)
{
}

Thread::~Thread()
{
	if (thread != 0)
	{
#ifdef HAVE_PTHREAD_H
		::pthread_join((pthread_t)thread, 0);
#elif defined(WIN32)
		::CloseHandle((HANDLE)thread);
#endif
		LOGLOG_DEBUG(_T("Thread ended."));
	}
}

unsigned long Thread::getCurrentThreadId()
{
#ifdef HAVE_PTHREAD_H
	return (unsigned long)::pthread_self();
#elif defined(WIN32)
	return ::GetCurrentThreadId();
#endif
}

void Thread::start()
{
#ifdef HAVE_PTHREAD_H
//	LogLog::debug(_T("Thread::start"));
	if (::pthread_create((pthread_t *)&thread, NULL, threadProc, this) != 0)
	{
		throw ThreadException();
	}
#elif defined(WIN32)
	unsigned long threadId = 0;
	thread =
		(void *)::CreateThread(NULL, 0, threadProc, this, 0, &threadId);
	if (thread == 0)
	{
		throw ThreadException();
	}
#endif
}

void Thread::run()
{
	if (runnable != 0)
	{
		runnable->run();
	}
}

void Thread::join()
{
	bool bSuccess = true;
#ifdef HAVE_PTHREAD_H
	::pthread_join((pthread_t)thread, 0);
#elif defined(WIN32)
	if (::WaitForSingleObject((HANDLE)thread, INFINITE) != WAIT_OBJECT_0)
	{
		bSuccess = false;
	}

	::CloseHandle((HANDLE)thread);
#endif

	thread = 0;

	if (!bSuccess)
	{
		throw InterruptedException();
	}

	LOGLOG_DEBUG(_T("Thread ended."));
}

void Thread::sleep(long millis)
{
#ifdef WIN32
	::Sleep(millis);
#else
	::usleep(1000 * millis);
#endif
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
