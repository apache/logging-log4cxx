/***************************************************************************
                          semaphore.h  -  Semaphore
                             -------------------
    begin                : lun avr 21 2003
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

#ifndef _LOG4CXX_HELPERS_SEMAPHORE_H
#define _LOG4CXX_HELPERS_SEMAPHORE_H

#include <log4cxx/config.h>
#include <log4cxx/helpers/exception.h>

#ifdef HAVE_PTHREAD
#include <semaphore.h>
#endif

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT SemaphoreException : public Exception
		{
		};

#ifdef HAVE_MS_THREAD
		class Condition;
#endif

		class LOG4CXX_EXPORT Semaphore
		{
#ifdef HAVE_MS_THREAD
		friend class Condition;
#endif
		public:
			Semaphore(int value = 0);
			~Semaphore();
			void wait();
			bool tryWait();
			void post();

		protected:
#ifdef HAVE_PTHREAD
			sem_t semaphore;
#elif defined (HAVE_MS_THREAD)
			void * semaphore;
#endif
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPERS_SEMAPHORE_H
