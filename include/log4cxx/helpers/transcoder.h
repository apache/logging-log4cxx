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

#ifndef _LOG4CXX_HELPERS_TRANSCODER_H
#define _LOG4CXX_HELPERS_TRANSCODER_H

#include <log4cxx/logstring.h>
#include <log4cxx/portability.h>
#include <string.h>
#include <wchar.h>

class apr_pool_t;

namespace log4cxx {
   namespace helpers {
     /**
     *    Simple transcoder for converting between
     *      external char and wchar_t strings and
     *      internal strings.
     *
     */
      class LOG4CXX_EXPORT Transcoder {
      public:
      /**
      *   Appends an external string to an
      *     internal string.
      */
      static void decode(const char* src, size_t len, LogString& dst);
      static void decode(const wchar_t* src, size_t len, LogString& dst);

      //
      //   convienience wrappers
      //
      inline static void decode(const char* src, LogString& dst) {
        decode(src, strlen(src), dst);
      }

      inline static void decode(const wchar_t* src, LogString& dst) {
        decode(src, wcslen(src), dst);
      }

      template<class SRC>
      inline static void decode(const SRC& src, LogString& dst) {
        decode(src.data(), src.length(), dst);
      }

      /**
      *   Determines if the buffer contains Unicode or multibyte
      *     and returns equivalent internal string.
      */
      static void decode(const void* src, size_t byteCount,
            LogString& dst);


      /**
      *   Appends an internal string to an
      *     external string.
      */
      static void encode(const LogString& src, std::string& dst);
      static void encode(const LogString& src, std::wstring& dst);


      private:

      private:
      Transcoder();
      Transcoder(const Transcoder&);
      Transcoder& operator=(const Transcoder&);
      enum { BUFSIZE = 256 };
      static const Transcoder& detect(unsigned char byte0, unsigned char byte1, size_t* offset);
      };
   }
};

#define LOG4CXX_ENCODE_CHAR(var, src) \
std::string var;                      \
log4cxx::helpers::Transcoder::encode(src, var)

#define LOG4CXX_DECODE_CHAR(var, src) \
log4cxx::LogString var;                      \
log4cxx::helpers::Transcoder::decode(src, var)


#if defined(LOG4CXX_LOGCHAR_IS_WCHAR)

#define LOG4CXX_ENCODE_WCHAR(var, src) \
const std::wstring& var = src;

#define LOG4CXX_DECODE_WCHAR(var, src) \
const log4cxx::LogString& var = src;

#endif


#if defined(LOG4CXX_LOGCHAR_IS_CHAR)

#define LOG4CXX_ENCODE_WCHAR(var, src) \
std::wstring var;                      \
log4cxx::helpers::Transcoder::encode(src, var)

#define LOG4CXX_DECODE_WCHAR(var, src) \
log4cxx::LogString var;                      \
log4cxx::helpers::Transcoder::decode(src, var)

#endif


#endif //_LOG4CXX_HELPERS_TRANSCODER_H
