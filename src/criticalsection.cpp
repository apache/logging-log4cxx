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
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/helpers/criticalsection.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#elif defined(WIN32)
#include <windows.h>
#endif

using namespace log4cxx::helpers;

CriticalSection::CriticalSection()
{
#ifdef HAVE_PTHREAD_H
	mutex = new pthread_mutex_t;
	pthread_mutex_init((pthread_mutex_t*)mutex, NULL);
#elif defined(WIN32)
	mutex = new CRITICAL_SECTION;
	InitializeCriticalSection((CRITICAL_SECTION *)mutex);
#endif						
}

CriticalSection::~CriticalSection()
{
#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy((pthread_mutex_t*)mutex);
	delete (pthread_mutex_t*)mutex;
#elif defined(WIN32)
	DeleteCriticalSection((CRITICAL_SECTION *)mutex);
	delete (CRITICAL_SECTION *)mutex;
#endif
}

void CriticalSection::lock()
{
#ifdef HAVE_PTHREAD_H
	pthread_mutex_lock((pthread_mutex_t*)mutex);
#elif defined(WIN32)
	EnterCriticalSection((CRITICAL_SECTION *)mutex);
#endif
}

void CriticalSection::unlock()
{
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock((pthread_mutex_t*)mutex);
#elif defined(WIN32)
	LeaveCriticalSection((CRITICAL_SECTION *)mutex);
#endif
}
