/***************************************************************************
                          thread.h  -  class Thread
                             -------------------
    begin                : jeu mai 8 2003
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

#ifndef _LOG4CXX_HELPERS_THREAD_H
#define _LOG4CXX_HELPERS_THREAD_H

#include <log4cxx/config.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		class ThreadException : Exception
		{
		public:
			String getMessage() { return String(); }
		};

		class InterruptedException : Exception
		{
		public:
			String getMessage() { return String(); }
		};
		
		/** The Runnable interface should be implemented by any class whose 
		instances are intended to be executed by a thread. 
		The class must define a method of no arguments called run.
		*/
		class Runnable : public virtual Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(Runnable)

			/** When an object implementing interface Runnable is used to
			create a thread, starting the thread causes the object's run 
			method to be called in that separately executing thread.
			*/
			virtual void run() = 0;
		};

		typedef ObjectPtrT<Runnable> RunnablePtr;
		
		/** A thread is a thread of execution in a program.
		*/
		class Thread : public virtual ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(Thread)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(Thread)
			END_LOG4CXX_CAST_MAP()

			/**  Allocates a new Thread object.*/
			Thread();
			
			/**  Allocates a new Thread object.*/
			Thread(RunnablePtr runnable);
			
			virtual ~Thread();

			/** Returns the current thread identifier
			*/
			static unsigned long getCurrentThreadId();

			/** Causes the currently executing thread to sleep (temporarily
			cease execution) for the specified number of milliseconds.
			*/
			static void sleep(long millis);

			/** Causes this thread to begin execution;
			calls the run method of this thread.
			*/
			void start();

			/**  If this thread was constructed using a separate Runnable
			run object, then that Runnable object's run method is called;
			otherwise, this method does nothing and returns.
			*/
			virtual void run();

			/** Waits for this thread to die.
			*/
			void join();

			enum
			{
				MIN_PRIORITY = 1,
				NORM_PRIORITY = 2,
				MAX_PRIORITY = 3 
			};

			/** Changes the priority of this thread.
			*/
			void setPriority(int newPriority);

		protected:
			/** Thread descriptor */
			void * thread;
			RunnablePtr runnable;
		};
	}; // namespace helpers
}; //namespace log4cxx

#endif // _LOG4CXX_HELPERS_THREAD_H
