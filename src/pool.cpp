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
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/aprinitializer.h>
#include <apr_pools.h>
#include <assert.h>

using namespace log4cxx::helpers;
using namespace log4cxx;


Pool::Pool() : pool(0), release(true) {
    apr_pool_t* aprPool;
    apr_status_t stat = apr_pool_create(&aprPool, APRInitializer::getRootPool());
    if (stat != APR_SUCCESS) {
        throw PoolException(stat);
    }
    pool = aprPool;
}

Pool::Pool(log4cxx_pool_t* p, bool release1) : pool((apr_pool_t*) p), release(release1) {
    assert(p != NULL);
}

Pool::~Pool() {
    if (release) {
      apr_pool_destroy((apr_pool_t*) pool);
    }
}


const log4cxx_pool_t* Pool::getAPRPool() {
   return pool;
}

char* Pool::palloc(size_t size) {
  return (char*) apr_palloc((apr_pool_t*) pool, size);
}
