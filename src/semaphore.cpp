/***************************************************************************
                          semaphore.cpp  -  class Semaphore
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
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/helpers/semaphore.h>

#ifdef HAVE_PTHREAD
#include <semaphore.h>
#elif defined(HAVE_MS_THREAD)
#include <windows.h>
#include <limits.h>
#endif

using namespace log4cxx::helpers;

Semaphore::Semaphore(int value)
{
#ifdef HAVE_PTHREAD
	if (::sem_init(&semaphore, 0, value) != 0)
	{
		throw SemaphoreException();
	}
#elif defined(HAVE_MS_THREAD)
	semaphore = ::CreateSemaphore(0, (long)value, LONG_MAX, 0);
	if (semaphore == 0)
	{
		throw SemaphoreException();
	}
#endif						
}

Semaphore::~Semaphore()
{
#ifdef HAVE_PTHREAD
	::sem_destroy(&semaphore);
#elif defined(HAVE_MS_THREAD)
	::CloseHandle(semaphore);
#endif
}

void Semaphore::wait()
{
#ifdef HAVE_PTHREAD
	if (::sem_wait(&semaphore) != 0)
	{
		throw SemaphoreException();
	}
#elif defined(HAVE_MS_THREAD)
	if (::WaitForSingleObject(semaphore, INFINITE) != WAIT_OBJECT_0)
	{
		throw SemaphoreException();
	}
#endif
}

bool Semaphore::tryWait()
{
#ifdef HAVE_PTHREAD
	return (::sem_trywait(&semaphore) == 0);
#elif defined(HAVE_MS_THREAD)
	bool bSuccess;
	switch(::WaitForSingleObject(semaphore, 0))
	{
	case WAIT_OBJECT_0:
		bSuccess = true;
		break;
	case WAIT_TIMEOUT:
		bSuccess = false;
		break;
	default:
		throw SemaphoreException();
		break;
	}
	return bSuccess;
#endif
}

void Semaphore::post()
{
#ifdef HAVE_PTHREAD
	if (::sem_post(&semaphore) != 0)
	{
		throw SemaphoreException();
	}
#elif defined(HAVE_MS_THREAD)
	long previousCount;
	if (!::ReleaseSemaphore(semaphore, 1, &previousCount))
	{
		throw SemaphoreException();
	}
#endif
}

