/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/
 
#ifndef _LOG4CXX_HELPERS_EVENT_H
#define _LOG4CXX_HELPERS_EVENT_H
 
#include <log4cxx/config.h>
#include <log4cxx/helpers/exception.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif
 
namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT EventException : public Exception
		{
		public:
			EventException(const String& message) : Exception(message)
			{
			}
		};
		
		/**
		Object to be used to synchronize threads
		
		An event is signalled with set().  If the new event is
		a manual reset event, it remains signalled until it is reset
		with reset().  An auto reset event remains signalled until a
		single thread has waited for it, at which time the event handle is
		automatically reset to unsignalled.
		*/
		class LOG4CXX_EXPORT Event
		{
		public:
			/** 
			Creates a new event
			
			@param manualReset Specifies whether the new event has manual or auto
			reset behaviour.
			@param initialState Specifies whether the new event handle is initially
 			signalled or not
			*/
			Event(bool manualReset, bool initialState);
			
			/**
			Destroy the event
			*/
			~Event();
			
			/**
			Sets the event to the signalled state.

			If the event is a manual reset event, it remains signalled until it
			is reset with Reset().  An auto reset event remains signalled
			until a single thread has waited for it, at which time the event is
			automatically reset to unsignalled.
			*/
			void set();
			
			/** 
			Resets the event to the unsignalled state
			*/
			void reset();
			
			/** 
			Wait for the event to be set
			
			This method immediatly returns if the event is already set
			*/
			void wait();
			
		protected:
#ifdef HAVE_PTHREAD
			pthread_cond_t condition;
			pthread_mutex_t mutex;
			bool state;
			bool manualReset;
#elif defined(HAVE_MS_THREAD)
			void * event;
#endif 
		}; // class Event
	}; // namespace helpers
}; // namespace log4cx

#endif //_LOG4CXX_HELPERS_EVENT_H
