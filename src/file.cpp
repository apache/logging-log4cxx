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

File::File(const std::string& name)
  : name(), osName() {
  Transcoder::decode(name, this->name);
  Transcoder::encode(this->name, osName);
}

#if LOG4CXX_HAS_WCHAR_T
File::File(const std::wstring& name)
   : name(), osName() {
  Transcoder::decode(name, this->name);
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


//
//   Current implementation is limited to MBCS files
//
//
log4cxx_status_t File::write(const LogString& src, Pool& p) const {
  LogString output;
  apr_file_t* f = NULL;
  apr_status_t rv = open(&f,
       APR_WRITE | APR_TRUNCATE | APR_CREATE, APR_OS_DEFAULT, p);
  if (rv == APR_SUCCESS) {
    std::string encoded;
    Transcoder::encode(src, encoded);
    size_t len = encoded.length();
    rv = apr_file_write(f, encoded.data(), &len);
    apr_status_t close = apr_file_close(f);
    assert(close == APR_SUCCESS);
  }
  return rv;
}


std::vector<LogString> File::list(Pool& p) const {
  return std::vector<LogString>();
  //
  //  TODO:
}
