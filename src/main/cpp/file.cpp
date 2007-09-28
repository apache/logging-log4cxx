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
#include <log4cxx/file.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/pool.h>
#include <assert.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

File::File() {
}

File::File(const std::string& name1)
  : name(), osName() {
  Transcoder::decode(name1, this->name);
  Transcoder::encode(this->name, osName);
}

#if LOG4CXX_HAS_WCHAR_T
File::File(const std::wstring& name1)
   : name(), osName() {
  Transcoder::decode(name1, this->name);
  Transcoder::encode(this->name, osName);
}
#endif

File::File(const File& src)
  : name(src.name), osName(src.osName) {
}

File& File::operator=(const File& src) {
  if (this == &src) return *this;

  name.assign(src.name);
  osName.assign(src.osName);

  return *this;
}


File::~File() {
}


log4cxx_status_t File::open(apr_file_t** file, int flags,
      int perm, Pool& p) const {
    //
    //   The trunction to MBCS can corrupt filenames
    //       would be nice to be able to do something about
    //       it here since we have both Unicode
    //          and local code page file names
    //
    return apr_file_open(file, osName.c_str(), flags, perm, (apr_pool_t*) p.getAPRPool());
}



bool File::exists(Pool& p) const {
  apr_finfo_t finfo;
  apr_status_t rv = apr_stat(&finfo, osName.c_str(),
        0, (apr_pool_t*) p.getAPRPool());
  return rv == APR_SUCCESS;
}

std::string File::convertBackSlashes(const std::string& src) {
  std::string::size_type pos = src.find('\\');
  if (pos == std::string::npos) {
    return src;
  }
  std::string mod(src);
  while(pos != std::string::npos) {
    mod[pos] = '/';
    pos = mod.find('\\');
  }
  return mod;
}

bool File::deleteFile(Pool& p) const {
  apr_status_t rv = apr_file_remove(convertBackSlashes(osName).c_str(),
        (apr_pool_t*) p.getAPRPool());
  return rv == APR_SUCCESS;
}

bool File::renameTo(const File& dest, Pool& p) const {
  apr_status_t rv = apr_file_rename(convertBackSlashes(osName).c_str(),
        convertBackSlashes(dest.getOSName()).c_str(),
        (apr_pool_t*) p.getAPRPool());
  return rv == APR_SUCCESS;
}


size_t File::length(Pool& pool) const {
  apr_finfo_t finfo;
  apr_status_t rv = apr_stat(&finfo, osName.c_str(),
        APR_FINFO_SIZE, (apr_pool_t*) pool.getAPRPool());
  if (rv == APR_SUCCESS) {
    return (size_t) finfo.size;
  }
  return 0;
}


log4cxx_time_t File::lastModified(Pool& pool) const {
  apr_finfo_t finfo;
  apr_status_t rv = apr_stat(&finfo, osName.c_str(),
        APR_FINFO_MTIME, (apr_pool_t*) pool.getAPRPool());
  if (rv == APR_SUCCESS) {
    return finfo.mtime;
  }
  return 0;
}


std::vector<LogString> File::list(Pool& p) const {
    apr_dir_t *dir;
    apr_finfo_t entry;
    std::vector<LogString> filenames;

    apr_status_t stat = apr_dir_open(&dir, 
        convertBackSlashes(osName).c_str(), 
        (apr_pool_t*) p.getAPRPool());
    if(stat == APR_SUCCESS) {
        stat = apr_dir_read(&entry, APR_FINFO_DIRENT, dir);
        while(stat == APR_SUCCESS) {
            if (entry.name != NULL) {
               LOG4CXX_DECODE_CHAR(filename, entry.name);
               filenames.push_back(filename);
            }
            stat = apr_dir_read(&entry, APR_FINFO_DIRENT, dir);
        }
        stat = apr_dir_close(dir);
    }
    return filenames;
}

LogString File::getParent(Pool&) const {
     LogString::size_type slashPos = name.rfind(LOG4CXX_STR('/'));
     LogString::size_type backPos = name.rfind(LOG4CXX_STR('\\'));
     if (slashPos == LogString::npos) {
         slashPos = backPos;
     } else {
         if (backPos != LogString::npos && backPos > slashPos) {
             slashPos = backPos;
         }
     }
     LogString parent;
     if (slashPos != LogString::npos && slashPos > 0) {
          parent.assign(name, 0, slashPos);
     }
     return parent;
}

bool File::mkdirs(Pool& p) const {
     apr_status_t stat = apr_dir_make_recursive(convertBackSlashes(osName).c_str(),
          APR_OS_DEFAULT, (apr_pool_t*) p.getAPRPool());
     return stat == APR_SUCCESS;
}
