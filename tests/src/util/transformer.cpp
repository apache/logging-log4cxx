/*
 * Copyright 2003-2005 The Apache Software Foundation.
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

#include "transformer.h"
#include <log4cxx/file.h>
#include <apr_thread_proc.h>
#include <apr_pools.h>
#include <apr_file_io.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


void Transformer::transform(const File& in, const File& out,
        const std::vector<Filter *>& filters)
{
     log4cxx::Filter::PatternList patterns;
     for(std::vector<Filter*>::const_iterator iter = filters.begin();
         iter != filters.end();
         iter++) {
         
         const log4cxx::Filter::PatternList& thesePatterns = (*iter)->getPatterns();
         for (log4cxx::Filter::PatternList::const_iterator pattern = thesePatterns.begin();
              pattern != thesePatterns.end();
              pattern++) {
              patterns.push_back(*pattern);
         }
     }
     transform(in, out, patterns);
}

void Transformer::transform(const File& in, const File& out,
        const Filter& filter)
{
    transform(in, out, filter.getPatterns());
}


void Transformer::transform(const File& in, const File& out,
        const log4cxx::Filter::PatternList& patterns)
{
     apr_pool_t* pool;
     apr_status_t stat = apr_pool_create(&pool, NULL);

     apr_procattr_t* attr = NULL;
     stat = apr_procattr_create(&attr, pool);
     
     apr_file_t* child_out;
     apr_int32_t flags = APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE;
     stat = apr_file_open(&child_out, out.getOSName().c_str(), 
          flags, APR_OS_DEFAULT, pool);

     stat = apr_procattr_child_out_set(attr, child_out, NULL);
     
     const char** args = (const char**) 
          apr_palloc(pool, sizeof(*args) * patterns.size()*2 + 3);
     args[0] = "-E";
     int i = 1;
     std::string tmp;
     for (log4cxx::Filter::PatternList::const_iterator iter = patterns.begin();
          iter != patterns.end();
          iter++) {
          args[i++] = "-e";
          tmp = "s`";
          tmp.append(iter->first);
          tmp.append(1, '`');
          tmp.append(iter->second);
          tmp.append("`g");
          char* arg = (char*) apr_palloc(pool, tmp.length() + 1 * sizeof(char));
          strcpy(arg, tmp.c_str());
          args[i++] = arg;
     }
     
     args[i++] = in.getOSName().c_str();
     args[i] = NULL;
     		

     apr_proc_t pid;
     stat = apr_proc_create(&pid,"sed", args, NULL, attr, pool);
     
     int exitcode = -1;
     apr_exit_why_e exitwhy;
     stat = apr_proc_wait(&pid, &exitcode, &exitwhy, APR_WAIT);
                                           
     apr_pool_destroy(pool);

}