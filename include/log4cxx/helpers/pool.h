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

#ifndef _LOG4CXX_HELPERS_POOL_H
#define _LOG4CXX_HELPERS_POOL_H

#include <log4cxx/portability.h>
#include <string.h>

typedef void log4cxx_pool_t;

namespace log4cxx
{
        namespace helpers
        {
                class LOG4CXX_EXPORT Pool
                {
                public:
                        Pool();
                        Pool(log4cxx_pool_t* pool, bool release);
                        const log4cxx_pool_t* getAPRPool();
                        ~Pool();

                        char* palloc(size_t length);

                protected:
                        log4cxx_pool_t* pool;
                        const bool release;

                private:
                        Pool(const log4cxx::helpers::Pool&);
                        Pool& operator=(const Pool&);
                };
        } // namespace helpers
} // namespace log4cxx

#endif //_LOG4CXX_HELPERS_POOL_H
