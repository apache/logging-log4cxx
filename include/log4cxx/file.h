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

#ifndef _LOG4CXX_FILE_H
#define _LOG4CXX_FILE_H

#include <log4cxx/portability.h>
#include <log4cxx/logstring.h>

extern "C" {
struct apr_file_t;
struct apr_finfo_t;
struct apr_pool_t;
}

namespace log4cxx
{
                namespace helpers {
                  class Transcoder;
                }

                /**
                * An abstract representation of file and directory path names.
                */
                class LOG4CXX_EXPORT File
                {
                public:
                    File();
                    File(const std::string& name);
                    File(const std::wstring& name);
                    File(const File& src);
                    File& operator=(const File& src);
                    ~File();

                    bool exists(apr_pool_t* p) const;
                    size_t length(apr_pool_t* p) const;
                    log4cxx_time_t lastModified(apr_pool_t* p) const;
                    inline const LogString& getName() const {
                       return name;
                    }

#if defined(_MSC_VER)
                    LogString read(void* pool) const;
#else                    
                    LogString read(apr_pool_t* pool) const;
#endif

                    log4cxx_status_t write(const LogString& src, apr_pool_t* p) const;

                    log4cxx_status_t open(apr_file_t** file, int flags,
                          int perm, apr_pool_t* p) const;

                private:
                    LogString name;
                    std::string osName;
                };
} // namespace log4cxx


#define LOG4CXX_FILE(name) log4cxx::File(LOG4CXX_STR(name))

#endif // _LOG4CXX_FILE_H
