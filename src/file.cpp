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

using namespace log4cxx;
using namespace log4cxx::helpers;

File::File() {
}

#if defined(LOG4CXX_LOGCHAR_IS_WCHAR)
File::File(const std::string& name)
  : mbcsName(name) {
  Transcoder::decode(name, internalName);
}

File::File(const std::wstring& name)
   : internalName(name) {
  Transcoder::encode(name, mbcsName);
}
#endif

File::File(const File& src)
  : mbcsName(mbcsName), internalName(internalName) {
}

File& File::operator=(const File& src) {
  internalName.assign(src.internalName);
  mbcsName.assign(src.mbcsName);
}


File::~File() {
}

bool File::exists() const {
  Pool pool;
  apr_finfo_t finfo;
  apr_status_t rv = apr_stat(&finfo, mbcsName.c_str(),
        0, pool);
  return rv == APR_SUCCESS;
}


size_t File::length() const {
  Pool pool;
  apr_finfo_t finfo;
  apr_status_t rv = apr_stat(&finfo, mbcsName.c_str(),
        APR_FINFO_SIZE, pool);
  if (rv == APR_SUCCESS) {
    return finfo.size;
  }
  return 0;
}


apr_time_t File::lastModified() const {
  Pool pool;
  apr_finfo_t finfo;
  apr_status_t rv = apr_stat(&finfo, mbcsName.c_str(),
        APR_FINFO_MTIME, pool);
  if (rv == APR_SUCCESS) {
    return finfo.mtime;
  }
  return 0;
}


//
//   Current implementation is limited to MBCS files
//
//
LogString File::read(apr_pool_t* p) const {
  LogString output;
  apr_file_t* f = NULL;
  apr_status_t rv = apr_file_open(&f, mbcsName.c_str(), APR_READ, APR_OS_DEFAULT, p);
  if (rv == APR_SUCCESS) {
    const size_t BUFSIZE = 4096;
    char* buf = (char*) apr_palloc(p, BUFSIZE);
    char* contents = buf;
    apr_size_t contentLength = 0;
    apr_status_t rv;
    do {
      apr_size_t bytesRead = BUFSIZE;
      rv = apr_file_read(f, buf, &bytesRead);
      contentLength += bytesRead;
      if (rv == APR_EOF || (rv == APR_SUCCESS && bytesRead < BUFSIZE)) {
          //
          //     finished file
          //        transcode and exit
          Transcoder::decode(contents, contentLength, output);
          apr_file_close(f);
          return output;
      } else if (rv == APR_SUCCESS) {
         //
         //   file was larger than the buffer
         //      realloc a bigger buffer
         char* newContents =
             (char*) apr_palloc(p, contentLength + BUFSIZE);
         buf = newContents + contentLength;
         memcpy(newContents, contents, contentLength);
         //
         //   we would free contents here if you did that sort of thing
         //
         contents = newContents;
      }
    } while(rv == APR_SUCCESS);
  }
  apr_file_close(f);
  return output;
}



//
//   Current implementation is limited to MBCS files
//
//
apr_status_t File::write(const LogString& src, apr_pool_t* p) const {
  LogString output;
  apr_file_t* f = NULL;
  apr_status_t rv = apr_file_open(&f, mbcsName.c_str(),
       APR_WRITE | APR_TRUNCATE | APR_CREATE, APR_OS_DEFAULT, p);
  if (rv == APR_SUCCESS) {
    std::string encoded;
    Transcoder::encode(src, encoded);
    size_t len = encoded.length();
    rv = apr_file_write(f, encoded.data(), &len);
    apr_status_t close = apr_file_close(f);
  }
  return rv;
}
