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
 
#include <log4cxx/helpers/objectimpl.h>

#ifdef WIN32
#include <windows.h>
#endif

using namespace log4cxx::helpers;

ObjectImpl::ObjectImpl() : ref(0)
{
}

ObjectImpl::~ObjectImpl()
{
}

void ObjectImpl::addRef()
{
#ifdef HAVE_PTHREAD_H
	refCs.lock();
	ref++;
	refCs.unlock();
#elif defined(WIN32)
	::InterlockedIncrement((long *)&ref);
#else
	ref++;
#endif
}

void ObjectImpl::releaseRef()
{
#ifdef HAVE_PTHREAD_H
	refCs.lock();
	ref--;
	if (ref <= 0)
	{
		delete this;
	}
	refCs.unlock();
#elif defined(WIN32)
	if (::InterlockedDecrement((long *)&ref) <= 0)
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

void ObjectImpl::lock()
{
	cs.lock();
}

void ObjectImpl::unlock()
{
	cs.unlock();
}

void ObjectImpl::wait()
{
	sem.wait();
}

void ObjectImpl::notify()
{
	sem.post();
}
