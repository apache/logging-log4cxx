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

#include <log4cxx/helpers/condition.h>

#include <apr_thread_cond.h>
#include <log4cxx/helpers/synchronized.h>

using namespace log4cxx::helpers;
using namespace log4cxx;

Condition::Condition(apr_pool_t* p) 
{
	apr_status_t stat = apr_thread_mutex_create(&mutex,
		APR_THREAD_MUTEX_DEFAULT, p);
	if (stat != APR_SUCCESS) {
		throw ConditionException(stat);
	}
	stat = apr_thread_cond_create(&condition, p);
	if (stat != APR_SUCCESS) {
		throw ConditionException(stat);
	}
}

Condition::~Condition()
{
	apr_status_t stat = apr_thread_cond_destroy(condition);
	stat = apr_thread_mutex_destroy(mutex);
}

void Condition::broadcast()
{
	apr_status_t stat = apr_thread_cond_broadcast(condition);
	if (stat != APR_SUCCESS) {
		throw ConditionException(stat);
	}
}


void Condition::wait()
{
	synchronized sync(mutex);
	apr_status_t stat = apr_thread_cond_wait(condition, mutex);
	if (stat != APR_SUCCESS) {
		throw ConditionException(stat);
	}
}
