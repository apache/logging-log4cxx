/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/
 
#include <log4cxx/helpers/event.h>

#ifdef HAVE_MS_THREAD
#include <windows.h>
#endif 

using namespace log4cxx::helpers;

Event::Event(bool manualReset, bool initialState)
#ifdef HAVE_PTHREAD
: manualReset(manualReset), state(initialState)
#endif 
{
#ifdef HAVE_PTHREAD
	pthread_cond_init(&condition, 0);
	pthread_mutex_init(&mutex, 0);
#elif defined(HAVE_MS_THREAD)
	event = ::CreateEvent(
		NULL, 
		manualReset ? TRUE : FALSE, 
		initialState ? TRUE : FALSE, 
		NULL);
		
	if (event == NULL)
	{
		throw EventException(_T("Cannot create event"));
	}
#endif 
}

Event::~Event()
{
#ifdef HAVE_PTHREAD
	::pthread_cond_destroy(&condition);
	pthread_mutex_destroy(&mutex);
#elif defined(HAVE_MS_THREAD)
	::CloseHandle((HANDLE)event);
#endif 
}

void Event::set()
{
#ifdef HAVE_PTHREAD
	if (pthread_mutex_lock(&mutex) != 0)
	{
		throw EventException(_T("Cannot lock mutex"));
	}
	
	// if the event is already set, no need to signal or broadcast
	if (!state)
	{
		state = true;
		
		if(manualReset)
		{
			if (pthread_cond_broadcast(&condition) != 0)
			{
				pthread_mutex_unlock(&mutex);
				throw EventException(_T("Cannot broadcast condition"));
			}
		} 
		else
		{
			if (pthread_cond_signal(&condition) != 0)
			{
				pthread_mutex_unlock(&mutex);
				throw EventException(_T("Cannot signal condition"));
			}
		}
	}
	
	if (pthread_mutex_unlock(&mutex) != 0)
	{
		throw EventException(_T("Cannot unlock mutex"));
	}
#elif defined(HAVE_MS_THREAD)
	if (!::SetEvent((HANDLE)event))
	{
		throw EventException(_T("Cannot set event"));
	}
#endif 
}

void Event::reset()
{
#ifdef HAVE_PTHREAD
	if (pthread_mutex_lock(&mutex) != 0)
	{
		throw EventException(_T("Cannot lock mutex"));
	}
	
	state = false;
	
	if (pthread_mutex_unlock(&mutex) != 0)
	{
		throw EventException(_T("Cannot unlock mutex"));
	}
#elif defined(HAVE_MS_THREAD)
	if (!::ResetEvent((HANDLE)event))
	{
		throw EventException(_T("Cannot reset event"));
	}
#endif 
}

void Event::wait()
{
#ifdef HAVE_PTHREAD
	if (pthread_mutex_lock(&mutex) != 0)
	{
		throw EventException(_T("Cannot lock mutex"));
	}

	// we wait on condition only if the event is not set (state == false)
	if (!state && pthread_cond_wait(&condition, &mutex) != 0)
	{
		pthread_mutex_unlock(&mutex);
		throw EventException(_T("Cannot wait on condition"));
	}

	if (!manualReset)
	{
		// automatic event reset.
		state = false;
	}
	
	if (pthread_mutex_unlock(&mutex) != 0)
	{
		throw EventException(_T("Cannot unlock mutex"));
	}
#elif defined(HAVE_MS_THREAD)
	if (::WaitForSingleObject((HANDLE)event, INFINITE)
		!= WAIT_OBJECT_0)
	{
		throw EventException(_T("Wait on event error"));
	}
#endif 
}
