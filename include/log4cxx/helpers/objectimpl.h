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
#include <log4cxx/helpers/criticalsection.h>

namespace log4cxx
{
	namespace helpers
	{
		/** Implementation class for Object.*/
		class LOG4CXX_EXPORT ObjectImpl : public virtual Object
		{
		public:
			ObjectImpl();
			virtual ~ObjectImpl();
			void addRef() const;
			void releaseRef() const;
			virtual void lock() const;
			virtual void unlock() const;
			virtual void wait() const;
			virtual void notify() const;
			virtual void notifyAll() const;

		protected:
			mutable long volatile ref;
			mutable CriticalSection cs;
			mutable void * eventList;
		};
	};
};

#endif //_LOG4CXX_HELPERS_OBJECT_IMPL_H
