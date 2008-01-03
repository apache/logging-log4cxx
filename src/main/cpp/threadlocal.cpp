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

#include "log4cxx/helpers/threadlocal.h"
#include "apr_thread_proc.h"
#include "log4cxx/helpers/exception.h"

using namespace log4cxx::helpers;
using namespace log4cxx;

ThreadLocal::ThreadLocal() {
#if APR_HAS_THREADS
    apr_pool_t** ppool = reinterpret_cast<apr_pool_t**>(&pool);
    apr_status_t stat = apr_pool_create(ppool, 0);
    if (stat != APR_SUCCESS) {
        throw RuntimeException(stat);
    }
    apr_threadkey_t** pkey = reinterpret_cast<apr_threadkey_t**>(&key);
    stat = apr_threadkey_private_create(pkey, 0, (apr_pool_t*) pool);
    if (stat != APR_SUCCESS) {
         throw RuntimeException(stat);
    }
#endif
}
              
ThreadLocal::~ThreadLocal() {
#if APR_HAS_THREADS
    apr_pool_destroy((apr_pool_t*) pool);
#endif
}
              
void ThreadLocal::set(void* priv) {
#if APR_HAS_THREADS
    apr_status_t stat = apr_threadkey_private_set(priv, (apr_threadkey_t*) key);
    if (stat != APR_SUCCESS) {
        throw RuntimeException(stat);
    }
#endif
}
               
void* ThreadLocal::get() {
    void* retval = 0;
#if APR_HAS_THREADS
    apr_status_t stat = apr_threadkey_private_get(&retval, (apr_threadkey_t*) key);
    if (stat != APR_SUCCESS) {
        throw RuntimeException(stat);
    }
#endif
    return retval;
}
