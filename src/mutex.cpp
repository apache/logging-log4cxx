/***************************************************************************
                          mutex.cpp  -  class Mutex
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

#include <log4cxx/config.h>

#ifdef HAVE_MS_THREAD
#include <windows.h>
#endif

#include <log4cxx/helpers/mutex.h>

using namespace log4cxx::helpers;
using namespace log4cxx;

Mutex::Mutex()
{
#ifdef HAVE_PTHREAD
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mutex, &attr);
	pthread_mutexattr_destroy(&attr);
#elif defined(HAVE_MS_THREAD)
	mutex = ::CreateMutex(0, 0, 0);
#endif
}

Mutex::~Mutex()
{
#ifdef HAVE_PTHREAD
	pthread_mutex_destroy(&mutex);
#elif defined(HAVE_MS_THREAD)
	::CloseHandle(mutex);
#endif
}

void Mutex::lock()
{
#ifdef HAVE_PTHREAD
	if (pthread_mutex_lock(&mutex) != 0)
	{
		throw MutexException();
	}
#elif defined(HAVE_MS_THREAD)
	if (::WaitForSingleObject(mutex, INFINITE) == WAIT_ABANDONED)
	{
		throw MutexException();
	}
#endif
}

void Mutex::unlock()
{
#ifdef HAVE_PTHREAD
	if (pthread_mutex_unlock(&mutex) != 0)
	{
		throw MutexException();
	}
#elif defined(HAVE_MS_THREAD)
	if (!::ReleaseMutex(mutex))
	{
		throw MutexException();
	}
#endif
}
