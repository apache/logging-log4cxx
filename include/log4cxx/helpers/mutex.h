/***************************************************************************
                          mutex.h  -  Mutex
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

#ifndef _LOG4CXX_HELPERS_MUTEX_H
#define _LOG4CXX_HELPERS_MUTEX_H

#include <log4cxx/config.h>
#include <log4cxx/helpers/exception.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

namespace log4cxx
{
	namespace helpers
	{
		class MutexException : public Exception
		{
		public: 
			virtual String getMessage() { return String();}
		};

		class Condition;

		class Mutex
		{
		friend class Condition;
		public:
			Mutex();
			~Mutex();
			void lock();
			void unlock();

		protected:
#ifdef HAVE_PTHREAD
			pthread_mutex_t mutex;
#elif defined(HAVE_MS_THREAD)
			void * mutex;
#endif
		};
	};// namespace helpers
};// namespace log4cxx

#endif //_LOG4CXX_HELPERS_MUTEX_H
