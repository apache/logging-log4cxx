/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/helpers/event.h>

#ifdef LOG4CXX_HAVE_MS_THREAD
#include <windows.h>
#endif

using namespace log4cxx::helpers;

//
//   Specializations of EventException, not in header since they
//      are subject to change and not part of public API
//
namespace log4cxx {
  namespace helpers {

    class CannotLockMutexException : public EventException
    {
    public:
          CannotLockMutexException()  {
          }
          const char* what() const throw() {
            return "Cannot lock mutex";
          }
    };

    class CannotBroadcastConditionException : public EventException
    {
    public:
         CannotBroadcastConditionException()  {
         }
         const char* what() const throw() {
             return "Cannot broadcast condition";
         }
    };

    class CannotSignalConditionException : public EventException
    {
        public:
        CannotSignalConditionException()  {
        }
        const char* what() const throw() {
            return "Cannot signal condition";
        }
    };

    class CannotUnlockMutexException : public EventException
    {
        public:
        CannotUnlockMutexException()  {
        }
        const char* what() const throw() {
            return "Cannot unlock mutex";
        }
    };

    class CannotSetEventException : public EventException
    {
        public:
        CannotSetEventException()  {
        }
        const char* what() const throw() {
            return "Cannot set event";
        }
    };

    class CannotCreateEventException : public EventException
    {
        public:
        CannotCreateEventException()  {
        }
        const char* what() const throw() {
            return "Cannot create event";
        }
    };

    class CannotWaitOnConditionException : public EventException
    {
        public:
        CannotWaitOnConditionException()  {
        }
        const char* what() const throw() {
            return "Cannot wait on condition";
        }
    };

    class WaitOnEventException : public EventException
    {
        public:
        WaitOnEventException()  {
        }
        const char* what() const throw() {
            return "Wait on event error";
        }
    };

  }
}


Event::Event(bool manualReset, bool initialState)
: condition(), mutex()
#ifdef LOG4CXX_HAVE_PTHREAD
  , manualReset(manualReset), state(initialState)
#endif
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_cond_init(&condition, 0);
	pthread_mutex_init(&mutex, 0);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	event = ::CreateEvent(
		NULL,
		manualReset ? TRUE : FALSE,
		initialState ? TRUE : FALSE,
		NULL);

	if (event == NULL)
	{
		throw CannotCreateEventException();
	}
#endif
}

Event::~Event()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	::pthread_cond_destroy(&condition);
	pthread_mutex_destroy(&mutex);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	::CloseHandle((HANDLE)event);
#endif
}

void Event::set()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	if (pthread_mutex_lock(&mutex) != 0)
	{
		throw CannotLockMutexException();
	}

	// if the event is already set, no need to signal or broadcast
	if (!state)
	{
		state = true;

		if(manualReset)
		{
			if (pthread_cond_broadcast(&condition) != 0)
			{
				pthread_mutex_unlock(&mutex);
				throw CannotBroadcastConditionException();
			}
		}
		else
		{
			if (pthread_cond_signal(&condition) != 0)
			{
				pthread_mutex_unlock(&mutex);
				throw CannotSignalConditionException();
			}
		}
	}

	if (pthread_mutex_unlock(&mutex) != 0)
	{
		throw CannotUnlockMutexException();
	}
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	if (!::SetEvent((HANDLE)event))
	{
		throw CannotSetEventException();
	}
#endif
}

void Event::reset()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	if (pthread_mutex_lock(&mutex) != 0)
	{
		throw CannotLockMutexException();
	}

	state = false;

	if (pthread_mutex_unlock(&mutex) != 0)
	{
		throw CannotUnlockMutexException();
	}
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	if (!::ResetEvent((HANDLE)event))
	{
		throw CannotResetEventException();
	}
#endif
}

void Event::wait()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	if (pthread_mutex_lock(&mutex) != 0)
	{
		throw CannotUnlockMutexException();
	}

	// we wait on condition only if the event is not set (state == false)
	if (!state && pthread_cond_wait(&condition, &mutex) != 0)
	{
		pthread_mutex_unlock(&mutex);
		throw CannotWaitOnConditionException();
	}

	if (!manualReset)
	{
		// automatic event reset.
		state = false;
	}

	if (pthread_mutex_unlock(&mutex) != 0)
	{
		throw CannotUnlockMutexException();
	}
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	if (::WaitForSingleObject((HANDLE)event, INFINITE)
		!= WAIT_OBJECT_0)
	{
		throw WaitOnEventException();
	}
#endif
}
