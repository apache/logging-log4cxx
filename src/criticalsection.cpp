/***************************************************************************
                          criticalsection.cpp  -  class CriticalSection
                             -------------------
    begin                : mar avr 22 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include <log4cxx/helpers/criticalsection.h>
#include <log4cxx/helpers/thread.h>

using namespace log4cxx::helpers;

CriticalSection::CriticalSection() : owningThread(0)
{
#ifdef HAVE_PTHREAD
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mutex, &attr);
	pthread_mutexattr_destroy(&attr);
#elif defined(HAVE_MS_THREAD)
	InitializeCriticalSection(&mutex);
#endif						
}

CriticalSection::~CriticalSection()
{
#ifdef HAVE_PTHREAD
	pthread_mutex_destroy(&mutex);
#elif defined(HAVE_MS_THREAD)
	DeleteCriticalSection(&mutex);
#endif
}

void CriticalSection::lock()
{
#ifdef HAVE_PTHREAD
	pthread_mutex_lock(&mutex);
#elif defined(HAVE_MS_THREAD)
	EnterCriticalSection(&mutex);
#endif
	owningThread = Thread::getCurrentThreadId();
}

void CriticalSection::unlock()
{
	owningThread = 0;

#ifdef HAVE_PTHREAD
	pthread_mutex_unlock(&mutex);
#elif defined(HAVE_MS_THREAD)
	LeaveCriticalSection(&mutex);
#endif
}

unsigned long CriticalSection::getOwningThread()
{
	return owningThread;
}
