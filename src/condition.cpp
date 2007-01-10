/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/condition.h>
#include <log4cxx/helpers/exception.h>

#include <apr_thread_cond.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/helpers/pool.h>

using namespace log4cxx::helpers;
using namespace log4cxx;

#if APR_HAS_THREADS


Condition::Condition(Pool& p)
{
        apr_pool_t* aprPool = (apr_pool_t*) p.getAPRPool();
        apr_thread_mutex_t* aprMutex = NULL;
        apr_status_t stat = apr_thread_mutex_create(&aprMutex,
                APR_THREAD_MUTEX_DEFAULT, aprPool);
        if (stat != APR_SUCCESS) {
                throw ConditionException(stat);
        }
        mutex = aprMutex;
        apr_thread_cond_t* aprCondition = NULL;
        stat = apr_thread_cond_create(&aprCondition, aprPool);
        if (stat != APR_SUCCESS) {
                stat = apr_thread_mutex_destroy(aprMutex);
                throw ConditionException(stat);
        }
        condition = aprCondition;
}

Condition::~Condition()
{
        apr_thread_cond_destroy((apr_thread_cond_t*) condition);
        apr_thread_mutex_destroy((apr_thread_mutex_t*)mutex);
}

void Condition::broadcast()
{
        apr_status_t stat = apr_thread_cond_broadcast((apr_thread_cond_t*) condition);
        if (stat != APR_SUCCESS) {
                throw ConditionException(stat);
        }
}


void Condition::wait()
{
        apr_status_t stat = apr_thread_mutex_lock((apr_thread_mutex_t*) mutex);
        if (stat != APR_SUCCESS) {
           throw MutexException(stat);
        }
        stat = apr_thread_cond_wait(
             (apr_thread_cond_t*) condition,
             (apr_thread_mutex_t*) mutex);
        if (stat != APR_SUCCESS) {
                throw ConditionException(stat);
        }
        stat = apr_thread_mutex_unlock((apr_thread_mutex_t*) mutex);
        if (stat != APR_SUCCESS) {
           throw MutexException(stat);
        }
}

#endif
