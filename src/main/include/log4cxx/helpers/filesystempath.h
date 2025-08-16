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

#ifndef LOG4CXX_FILE_SYSTEM_PATH_HDR_
#define LOG4CXX_FILE_SYSTEM_PATH_HDR_

#ifdef __has_include                           // Check if __has_include is present
#  if __has_include(<filesystem>)              // Check for a standard version
#    include <filesystem>
#    if defined(__cpp_lib_filesystem)          // C++ >= 17
namespace LOG4CXX_NS { using Path = std::filesystem::path; }
#define LOG4CXX_HAS_FILESYSTEM_PATH 1
#    endif
#  else                                        // Not found at all
#define LOG4CXX_HAS_FILESYSTEM_PATH 0
#  endif
#endif // __has_include

#endif /* LOG4CXX_FILE_SYSTEM_PATH_HDR_ */
