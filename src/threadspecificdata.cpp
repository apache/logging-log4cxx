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
 
#include <log4cxx/portability.h>

#ifdef LOG4CXX_HAVE_PTHREAD
#include <pthread.h>
#elif defined(LOG4CXX_HAVE_MS_THREAD)
#include <windows.h>
#endif

#include <log4cxx/helpers/threadspecificdata.h>

using namespace log4cxx::helpers;

struct ThreadSpecificData::Impl
{
	Impl(): key(0) {}
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_key_t key;
//#elif defined(LOG4CXX_HAVE_MS_THREAD)
#else
	void * key;
#endif
};

ThreadSpecificData::ThreadSpecificData() : impl(new Impl)
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_key_create(&impl->key, NULL);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	impl->key = (void *)TlsAlloc();
#endif
}

ThreadSpecificData::ThreadSpecificData(void (*cleanup)(void*)): impl(new Impl)
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_key_create(&impl->key, cleanup);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
//	impl->key = (void *)TlsAlloc();
#error "Not implemented"
#endif
}

ThreadSpecificData::~ThreadSpecificData()
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_key_delete(impl->key);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	TlsFree((DWORD)impl->key);
#endif
}

void * ThreadSpecificData::GetData() const
{
#ifdef LOG4CXX_HAVE_PTHREAD
	return pthread_getspecific((pthread_key_t)impl->key);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	return TlsGetValue((DWORD)impl->key);
#else
	return impl->key;
#endif
}

void ThreadSpecificData::SetData(void * data)
{
#ifdef LOG4CXX_HAVE_PTHREAD
	pthread_setspecific((pthread_key_t)impl->key, data);
#elif defined(LOG4CXX_HAVE_MS_THREAD)
	TlsSetValue((DWORD)impl->key, data);
#else
	impl->key = data;
#endif
}


ThreadSpecificData_ptr<int> test;
