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
#include <assert.h>
#include <iostream>

using namespace log4cxx;
using namespace log4cxx::helpers;

#if !defined(APR_FOPEN_READ)
#define APR_FOPEN_READ APR_READ
#define APR_FOPEN_CREATE APR_CREATE
#define APR_FOPEN_WRITE APR_WRITE
#define APR_FOPEN_TRUNCATE APR_TRUNCATE
#define APR_FOPEN_APPEND APR_APPEND
#endif

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
    {
       apr_pool_t* pool;
       apr_status_t stat = apr_pool_create(&pool, NULL);


        //
        //    fairly naive file copy code
        //
        //
        apr_file_t* child_out;
        apr_int32_t flags = APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE;
        stat = apr_file_open(&child_out, out.getOSName().c_str(),
          flags, APR_OS_DEFAULT, pool);
        assert(stat == 0);

        apr_file_t* in_file;
        stat = apr_file_open(&in_file, in.getOSName().c_str(),
           APR_FOPEN_READ, APR_OS_DEFAULT, pool);
        assert(stat == 0);
        apr_size_t bufsize = 32000;
        void* buf = apr_palloc(pool, bufsize);
        apr_size_t bytesRead = bufsize;

        while(stat == 0 && bytesRead == bufsize) {
            stat = apr_file_read(in_file, buf, &bytesRead);
            if (stat == 0 && bytesRead > 0) {
                stat = apr_file_write(child_out, buf, &bytesRead);
                assert(stat == 0);
            }
        }
        stat = apr_file_close(child_out);
        assert(stat == 0);
        apr_pool_destroy(pool);
     }

     if (patterns.size() > 0) {
        apr_pool_t* pool;
        apr_status_t stat = apr_pool_create(&pool, NULL);
        //
        //   if there are patterns, invoke sed to execute the replacements
        //
        //
        apr_procattr_t* attr = NULL;
        stat = apr_procattr_create(&attr, pool);
        assert(stat == 0);

        //
        //   find the program on the path
        //
        stat = apr_procattr_cmdtype_set(attr, APR_PROGRAM_PATH);
        assert(stat == 0);

        //
        //   build the argument list
        //      using Q as regex separator on s command
        //
        const char** args = (const char**)
          apr_palloc(pool, 5 * sizeof(*args));
        int i = 0;

        //
        //   not well documented
        //     but the first arg is a duplicate of the executable name
        //
        args[i++] = "sed";

        //
        //   write the regex's to a temporary file since they
        //      may get mangled if passed as parameters
        //
        std::string regexName(in.getOSName());
        regexName.append(".sed");

        std::string regexArg("-f");
        regexArg.append(regexName);
        args[i++] = regexArg.c_str();

        args[i++] = "-i";
        //
        //    specify the input file
        args[i++] = out.getOSName().c_str();
        args[i] = NULL;


        apr_file_t* regexFile;
        apr_int32_t flags = APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE;
        stat = apr_file_open(&regexFile, 
               regexName.c_str(),
               APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE, APR_OS_DEFAULT, 
               pool);

        std::string tmp;
        for (log4cxx::Filter::PatternList::const_iterator iter = patterns.begin();
          iter != patterns.end();
          iter++) {
          tmp = "sQ";
          tmp.append(iter->first);
          tmp.append(1, 'Q');
          tmp.append(iter->second);
          tmp.append("Qg\n");
          apr_file_puts(tmp.c_str(), regexFile);
        }
        apr_file_close(regexFile);


        //
        //    set the output stream to go to the console
        //
        apr_file_t* child_out;
        stat = apr_file_open_stdout(&child_out, pool);
        assert(stat == 0);

        stat =  apr_procattr_child_out_set(attr, child_out, NULL);
        assert(stat == 0);

        //
        //   redirect the child's error stream this processes
        //
        apr_file_t* child_err;
        stat = apr_file_open_stderr(&child_err, pool);
        assert(stat == 0);
        stat =  apr_procattr_child_err_set(attr, child_err, NULL);
        assert(stat == 0);



        apr_proc_t pid;
        stat = apr_proc_create(&pid,"sed", args, NULL, attr, pool);
        assert(stat == 0);

        apr_proc_wait(&pid, NULL, NULL, APR_WAIT);
        apr_pool_destroy(pool);

     }


}
