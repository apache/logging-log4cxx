/***************************************************************************
                          objectimpl.cpp  -  class ObjectImpl
                             -------------------
    begin                : mer avr 16 2003
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

#include <log4cxx/helpers/objectimpl.h>

using namespace log4cxx::helpers;

#ifdef HAVE_LINUX_ATOMIC_OPERATIONS
ObjectImpl::ObjectImpl()
{
	ref.counter = 0;
}
#else
ObjectImpl::ObjectImpl() : ref(0)
{
}
#endif

ObjectImpl::~ObjectImpl()
{
}

void ObjectImpl::addRef() const
{
#ifdef HAVE_LINUX_ATOMIC_OPERATIONS
	atomic_inc(&ref);
#elif defined(HAVE_PTHREAD)
	refCs.lock();
	ref++;
	refCs.unlock();
#elif defined(HAVE_MS_THREAD)
#if _MSC_VER == 1200	// MSDEV 6
	::InterlockedIncrement((long *)&ref);
#else
	::InterlockedIncrement(&ref);
#endif
#else
	ref++;
#endif
}

void ObjectImpl::releaseRef() const
{
#ifdef HAVE_LINUX_ATOMIC_OPERATIONS
	if (atomic_dec_and_test(&ref))
	{
		delete this;
	}
#elif defined(HAVE_PTHREAD)
	refCs.lock();
	ref--;
	if (ref <= 0)
	{
		delete this;
	}
	refCs.unlock();
#elif defined(HAVE_MS_THREAD)
#if _MSC_VER == 1200	// MSDEV 6
	if (::InterlockedDecrement((long *)&ref) == 0)
#else
	if (::InterlockedDecrement(&ref) == 0)
#endif
	{
		delete this;
	}
#else
	ref--;
	if (ref <= 0)
	{
		delete this;
	}
#endif
}

void ObjectImpl::lock() const
{
	mutex.lock();
}

void ObjectImpl::unlock() const
{
	mutex.unlock();
}

void ObjectImpl::wait() const
{
	cond.wait(mutex);
}

void ObjectImpl::notify() const
{
	cond.signal();
}

