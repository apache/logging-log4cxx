/*
 * Copyright 2004 The Apache Software Foundation.
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

#include <log4cxx/helpers/aprinitializer.h>
#include <apr_pools.h>
#include <apr_atomic.h>
#include <apr_time.h>

using namespace log4cxx::helpers;
using namespace log4cxx;

APRInitializer::APRInitializer() {
    apr_initialize();
    apr_pool_create(&p, NULL);
    apr_atomic_init(p);
	startTime = apr_time_now();
}

APRInitializer::~APRInitializer() {
    apr_pool_destroy(p);
    apr_terminate();
}

log4cxx_time_t APRInitializer::initialize() {
  static APRInitializer init;
  return init.startTime;
}
