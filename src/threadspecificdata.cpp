/***************************************************************************
                          threadspecificdata.cpp  -  description
                             -------------------
    begin                : jeu avr 24 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <log4cxx/config.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#elif defined(HAVE_MS_THREAD)
#include <windows.h>
#endif

#include <log4cxx/helpers/threadspecificdata.h>

using namespace log4cxx::helpers;

ThreadSpecificData::ThreadSpecificData() : key(0)
{
#ifdef HAVE_PTHREAD
	pthread_key_create((pthread_key_t *)&key, NULL);
#elif defined(HAVE_MS_THREAD)
	key = (void *)TlsAlloc();
#endif
}

ThreadSpecificData::~ThreadSpecificData()
{
#ifdef HAVE_PTHREAD
	pthread_key_delete((pthread_key_t)key);
#elif defined(HAVE_MS_THREAD)
	TlsFree((DWORD)key);
#endif
}

void * ThreadSpecificData::GetData() const
{
#ifdef HAVE_PTHREAD
	return pthread_getspecific((pthread_key_t)key);
#elif defined(HAVE_MS_THREAD)
	return TlsGetValue((DWORD)key);
#else
	return key;
#endif
}

void ThreadSpecificData::SetData(void * data)
{
#ifdef HAVE_PTHREAD
	pthread_setspecific((pthread_key_t)key, data);
#elif defined(HAVE_MS_THREAD)
	TlsSetValue((DWORD)key, data);
#else
	key = data;
#endif
}
