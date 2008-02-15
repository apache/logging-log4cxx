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

#ifndef _LOG4CXX_FILE_H
#define _LOG4CXX_FILE_H

#include <log4cxx/logger.h>
#include <log4cxx/logstring.h>

extern "C" {
struct apr_file_t;
struct apr_finfo_t;
}

namespace log4cxx
{
                namespace helpers {
                  class Transcoder;
                  class Pool;
                }

                /**
                * An abstract representation of file and directory path names.
                */
                class LOG4CXX_EXPORT File
                {
                public:
                    File();
                    File(const char* name);
                    File(const std::string& name);
#if LOG4CXX_WCHAR_T_API
                    File(const wchar_t* name);
                    File(const std::wstring& name);
#endif
#if LOG4CXX_UNICHAR_API
                    File(const UniChar* name);
                    File(const std::basic_string<UniChar>& name);
#endif
#if LOG4CXX_CFSTRING_API
                    File(const CFStringRef& name);
#endif
                    File(const File& src);
                    File& operator=(const File& src);
                    ~File();
                    
                    bool exists(log4cxx::helpers::Pool& p) const;
                    size_t length(log4cxx::helpers::Pool& p) const;
                    log4cxx_time_t lastModified(log4cxx::helpers::Pool& p) const;
                    LogString getName() const;
                    LogString getPath() const;
                    File& setPath(const LogString&);

                    log4cxx_status_t open(apr_file_t** file, int flags,
                          int perm, log4cxx::helpers::Pool& p) const;

                    std::vector<LogString> list(log4cxx::helpers::Pool& p) const;

                    bool deleteFile(log4cxx::helpers::Pool& p) const;
                    bool renameTo(const File& dest, log4cxx::helpers::Pool& p) const;
                    
                    LogString getParent(log4cxx::helpers::Pool& p) const;
                    bool mkdirs(log4cxx::helpers::Pool& p) const;

                private:
                    LogString path;
                    static char* convertBackSlashes(char*);
                    char* getPath(log4cxx::helpers::Pool& p) const;
                };
} // namespace log4cxx


#define LOG4CXX_FILE(name) log4cxx::File(name)

#endif // _LOG4CXX_FILE_H
