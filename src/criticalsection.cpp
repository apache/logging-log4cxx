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

#include <log4cxx/helpers/criticalsection.h>
#include <log4cxx/helpers/thread.h>

#ifdef LOG4CXX_HAVE_PTHREAD
#include <pthread.h>
#elif defined(LOG4CXX_HAVE_MS_THREAD)
#include <windows.h>
#endif


using namespace log4cxx::helpers;

struct CriticalSection::Impl
{
	Impl(CriticalSection::Type type): owningThread(0), type(type) {}
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_mutex_t mutex;
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	CRITICAL_SECTION mutex;
#endif						
	unsigned long owningThread;
	CriticalSection::Type type;
};

CriticalSection::CriticalSection(Type type) : impl(new Impl(type))
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	switch(type)
	{
		case Simple:
			// to nothing, leave the default type
			break;
		case Recursive:
			pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
			break;
	};
	pthread_mutex_init(&impl->mutex, &attr);
	pthread_mutexattr_destroy(&attr);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	InitializeCriticalSection(&impl->mutex);
#endif						
}

CriticalSection::~CriticalSection()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_mutex_destroy(&impl->mutex);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	DeleteCriticalSection(&impl->mutex);
#endif
}

void CriticalSection::lock()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_mutex_lock(&impl->mutex);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	EnterCriticalSection(&impl->mutex);
#endif
	impl->owningThread = Thread::getCurrentThreadId();
}

bool CriticalSection::try_lock()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	if(pthread_mutex_trylock(&impl->mutex) == EBUSY)
		return false;
	else
		return true;
#elif defined(LOG4CXX_HAVE_MS_THREAD)
#error "try_lock is not implemented for msthread"
#endif
}

void CriticalSection::unlock()
{
	impl->owningThread = 0;

#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_mutex_unlock(&impl->mutex);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	LeaveCriticalSection(&impl->mutex);
#endif
}

unsigned long CriticalSection::getOwningThread()
{
	return impl->owningThread;
}
