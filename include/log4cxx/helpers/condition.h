/***************************************************************************
                          condition.h  -  Condition
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

#ifndef _LOG4CXX_HELPERS_CONDITION_H
#define _LOG4CXX_HELPERS_CONDITION_H

#include <log4cxx/config.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/mutex.h>
#include <log4cxx/helpers/semaphore.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

namespace log4cxx
{
	namespace helpers
	{
		class ConditionException : public Exception
		{
		public:
			virtual String getMessage() { return String();}
		};

		class Condition
		{
		public:
			Condition();
			~Condition();
			void broadcast();
			void signal();
			void wait(Mutex& mutex);
			void wait(Mutex& mutex, long timeOut);

		protected:
#ifdef HAVE_PTHREAD
			pthread_cond_t condition;
#elif defined(HAVE_MS_THREAD)
			/// Number of waiting threads.
			long volatile waiters;

			/// Queue up threads waiting for the condition to become signaled.
			Semaphore sema;

			/**
			* An auto reset event used by the broadcast/signal thread to wait
			* for the waiting thread(s) to wake up and get a chance at the
			* semaphore.
			*/
			void * waitersDone;

			/// Keeps track of whether we were broadcasting or just signaling.
			bool wasBroadCast;
#endif
		};
	};// namespace helpers
};// namespace log4cxx

#endif //_LOG4CXX_HELPERS_CONDITION_H
