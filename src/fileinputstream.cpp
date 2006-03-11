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

#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <apr_file_io.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/aprinitializer.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(FileInputStream)

FileInputStream::FileInputStream(const LogString& filename) {
    apr_fileperms_t perm = APR_OS_DEFAULT;
    apr_int32_t flags = APR_READ;
    LOG4CXX_ENCODE_CHAR(fn, filename);
    apr_status_t stat = apr_file_open((apr_file_t**) &fileptr,
        fn.c_str(), flags, perm, (apr_pool_t*) pool.getAPRPool());
    if (stat != APR_SUCCESS) {
      throw IOException(stat);
    }
}


FileInputStream::FileInputStream(const File& aFile) {
    apr_fileperms_t perm = APR_OS_DEFAULT;
    apr_int32_t flags = APR_READ;
    LOG4CXX_ENCODE_CHAR(fn, aFile.getName());
    apr_status_t stat = apr_file_open((apr_file_t**) &fileptr,
        fn.c_str(), flags, perm, (apr_pool_t*) pool.getAPRPool());
    if (stat != APR_SUCCESS) {
      throw IOException(stat);
    }
}


FileInputStream::~FileInputStream() {
  if (fileptr != NULL && !APRInitializer::isDestructed) {
    apr_file_close((apr_file_t*) fileptr);
  }
}


void FileInputStream::close() {
  apr_status_t stat = apr_file_close((apr_file_t*) fileptr);
  if (stat == APR_SUCCESS) {
    fileptr = NULL;
  } else {
    throw IOException(stat);
  }
}


int FileInputStream::read(char* buf, int off, int len) const {
  apr_size_t bytesRead = len;
  apr_status_t stat = apr_file_read((apr_file_t*) fileptr, buf + off, &bytesRead); 
  if (APR_STATUS_IS_EOF(stat)) {
    bytesRead = -1;
  } else {
    if (stat != APR_SUCCESS) {
      throw IOException(stat);
    }
  }

  return bytesRead;
}
