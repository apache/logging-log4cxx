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

      //
      //   convienience wrappers
      //
      inline static void decode(const char* src, LogString& dst) {
        decode(src, strlen(src), dst);
      }

      template<class SRC>
      inline static void decode(const SRC& src, LogString& dst) {
        decode(src.data(), src.length(), dst);
      }


      static LogString decode(const std::string& src) {
        LogString dst;
        decode(src, dst);
        return dst;
      }


      /**
      *   Appends an internal string to an
      *     external string.
      */
      static void encode(const LogString& src, std::string& dst);


      static bool equals(const char* str1, size_t len, const LogString& str2);

#if LOG4CXX_HAS_WCHAR_T
      static void decode(const wchar_t* src, size_t len, LogString& dst);

      inline static void decode(const wchar_t* src, LogString& dst) {
        decode(src, wcslen(src), dst);
      }

      static LogString decode(const std::wstring& src) {
        LogString dst;
        decode(src, dst);
        return dst;
      }

      static void encode(const LogString& src, std::wstring& dst);

      static bool equals(const wchar_t* str1, size_t len, const LogString& str2);

#endif



      private:

      private:
      Transcoder();
      Transcoder(const Transcoder&);
      Transcoder& operator=(const Transcoder&);
      enum { BUFSIZE = 256 };
      static const Transcoder& detect(unsigned char byte0, unsigned char byte1, size_t* offset);

      };
   }
}

#define LOG4CXX_ENCODE_CHAR(var, src) \
std::string var;                      \
log4cxx::helpers::Transcoder::encode(src, var)

#define LOG4CXX_DECODE_CHAR(var, src) \
log4cxx::LogString var;                      \
log4cxx::helpers::Transcoder::decode(src, var)

#define LOG4CXX_DECODE_CHAR_1PARAM(src) \
log4cxx::helpers::Transcoder::decode(src)


#if LOG4CXX_LOGCHAR_IS_WCHAR

#define LOG4CXX_ENCODE_WCHAR(var, src) \
const std::wstring& var = src

#define LOG4CXX_DECODE_WCHAR(var, src) \
const log4cxx::LogString& var = src

#define LOG4CXX_DECODE_WCHAR_1PARAM(src) \
src

#endif


#if LOG4CXX_LOGCHAR_IS_UTF8

#define LOG4CXX_ENCODE_WCHAR(var, src) \
std::wstring var;                      \
log4cxx::helpers::Transcoder::encode(src, var)

#define LOG4CXX_DECODE_WCHAR(var, src) \
log4cxx::LogString var;                      \
log4cxx::helpers::Transcoder::decode(src, var)

#define LOG4CXX_DECODE_WCHAR_1PARAM(src) \
log4cxx::helpers::Transcoder::decode(src)


#endif


#endif //_LOG4CXX_HELPERS_TRANSCODER_H
