/***************************************************************************
                          autodeleteobject.h  -  class AutoDeleteObject
                             -------------------
    begin                : mar avr 15 2003
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
 
#ifndef _LOG4CXX_HELPERS_OBJECT_IMPL_H
#define _LOG4CXX_HELPERS_OBJECT_IMPL_H

#include <log4cxx/config.h>
#include <log4cxx/helpers/object.h>

#ifdef HAVE_LINUX_ATOMIC_OPERATIONS
#include <asm/atomic.h>
#elif defined(HAVE_PTHREAD)
#include <log4cxx/helpers/criticalsection.h>
#endif

#include <log4cxx/helpers/mutex.h>
#include <log4cxx/helpers/condition.h>

namespace log4cxx
{
	namespace helpers
	{
		/** Implementation class for Object.*/
		class ObjectImpl : public virtual Object
		{
		public:
			ObjectImpl();
			virtual ~ObjectImpl();
			void addRef();
			void releaseRef();
			virtual void lock();
			virtual void unlock();
			virtual void wait();
			virtual void notify();

		protected:
#ifdef HAVE_LINUX_ATOMIC_OPERATIONS
			atomic_t ref;
#elif defined(HAVE_PTHREAD)
			CriticalSection refCs;
			unsigned int ref;
#elif defined(HAVE_MS_THREAD)
			long ref;
#else
			unsigned int ref;
#endif
			Mutex mutex;
			Condition cond;
		};
	};
};

#endif //_LOG4CXX_HELPERS_OBJECT_IMPL_H
