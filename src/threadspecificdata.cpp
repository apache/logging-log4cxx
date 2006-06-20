/*
 * Copyright 2003,2005 The Apache Software Foundation.
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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/threadspecificdata.h>
#include <log4cxx/helpers/aprinitializer.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx::helpers;


ThreadSpecificData::ThreadSpecificData()
    : ndcStack(), mdcMap() {
}

ThreadSpecificData::~ThreadSpecificData() {
}


log4cxx::NDC::Stack& ThreadSpecificData::getCurrentThreadStack() {
  return getCurrentData().ndcStack;
}

log4cxx::MDC::Map& ThreadSpecificData::getCurrentThreadMap() {
  return getCurrentData().mdcMap;
}

ThreadSpecificData& ThreadSpecificData::getCurrentData() {
#if APR_HAS_THREADS
  void* pData = NULL;
  apr_status_t stat = apr_threadkey_private_get(&pData, APRInitializer::getTlsKey());
  if (stat != APR_SUCCESS) {
    throw ThreadException(stat);
  }
  if (pData == NULL) {
    ThreadSpecificData* newData = new ThreadSpecificData();
    stat = apr_threadkey_private_set(newData, APRInitializer::getTlsKey());
    if (stat != APR_SUCCESS) {
      delete newData;
      throw ThreadException(stat);
    }
    return *newData;
  }
  return *((ThreadSpecificData*) pData);
#else
  static ThreadSpecificData data;
  return data;
#endif
}
