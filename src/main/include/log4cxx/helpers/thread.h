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

#ifndef _LOG4CXX_HELPERS_THREAD_H
#define _LOG4CXX_HELPERS_THREAD_H

#include <log4cxx/log4cxx.h>
#include <log4cxx/helpers/pool.h>

#if !defined(LOG4CXX_THREAD_FUNC)
#if defined(_WIN32)
#define LOG4CXX_THREAD_FUNC __stdcall
#else
#define LOG4CXX_THREAD_FUNC
#endif
#endif


namespace log4cxx
{
        namespace helpers
        {
                class Pool;
                typedef void log4cxx_thread_t;

				typedef void* (LOG4CXX_THREAD_FUNC *Runnable)(log4cxx_thread_t* thread, void* data);
                class LOG4CXX_EXPORT Thread
                {
                public:
                        Thread();
                        ~Thread();

                        void run(Runnable start, void* data);
                        void stop();
                        void join();
                        //
                        //  called on the worker thread to indicate
                        //    immediate exit from the start method
                        void ending();

                        inline bool isActive() { return thread != 0; }

                        static void sleep(log4cxx_time_t duration);

                private:
                        Pool p;
                        log4cxx_thread_t* thread;
                        volatile bool alive;
                        Thread(const Thread&);
                        Thread& operator=(const Thread&);
                };
        } // namespace helpers
} // namespace log4cxx

#endif //_LOG4CXX_HELPERS_THREAD_H
