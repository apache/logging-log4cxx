/***************************************************************************
                          object.h  -  class Object
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
 
#ifndef _LOG4CXX_HELPERS_OBJECT_H
#define _LOG4CXX_HELPERS_OBJECT_H

namespace log4cxx
{
	namespace helpers
	{
		/** base class for java-like objects.*/
		class Object
		{
		public:
			virtual ~Object() {}
			virtual void addRef() = 0;
			virtual void releaseRef() = 0;
			virtual void lock() = 0;
			virtual void unlock() = 0;
			virtual void wait() = 0;
			virtual void notify() = 0;
		};

		/** utility class for objects multi-thread synchronization.*/
		class synchronized
		{
		public:
			synchronized(Object * object) : object(object)
				{ object->lock(); }

			~synchronized()
				{ object->unlock(); }

		protected:
			Object * object;
		};
	};
};

#endif //_LOG4CXX_HELPERS_OBJECT_H
