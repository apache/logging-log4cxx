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

#include <log4cxx/helpers/thread.h>
#include <log4cxx/helpers/exception.h>
#include <apr_thread_proc.h>
#include <log4cxx/helpers/pool.h>

using namespace log4cxx::helpers;
using namespace log4cxx;


Thread::Thread() : thread(NULL), finished(false) {
}

Thread::~Thread() {
        join();
}


void Thread::run(Pool& p, apr_thread_start_t start, void* data) {
    if (thread != NULL && !finished) {
                throw ThreadException(0);
        }
        apr_threadattr_t* attrs;
        apr_status_t stat = apr_threadattr_create(&attrs, (apr_pool_t*) p.getAPRPool());
        if (stat != APR_SUCCESS) {
                throw ThreadException(stat);
        }
        stat = apr_thread_create(&thread, attrs, start, data, (apr_pool_t*) p.getAPRPool());
        if (stat != APR_SUCCESS) {
                throw ThreadException(stat);
        }
}



void Thread::stop() {
        if (thread != NULL && !finished) {
                apr_status_t stat = apr_thread_exit(thread, 0);
                finished = true;
                thread = NULL;
                if (stat != APR_SUCCESS) {
                        throw ThreadException(stat);
                }
        }
}

void Thread::join() {
        if (thread != NULL && !finished) {
                apr_status_t startStat;
                apr_status_t stat = apr_thread_join(&startStat, thread);
                finished = true;
                thread = NULL;
                if (stat != APR_SUCCESS) {
                        throw ThreadException(stat);
                }
        }
}

void Thread::ending() {
        finished = true;
}
