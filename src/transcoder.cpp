/*
 * Copyright 2004-2005 The Apache Software Foundation.
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

#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/pool.h>
#include <stdlib.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/charsetencoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


bool Transcoder::equals(const char* str1, size_t len, const LogString& str2) {
    if (len == str2.length()) {
        LogString decoded;
        decode(str1, len, decoded);
        return decoded == str2;
    }
    return false;
}

#if LOG4CXX_HAS_WCHAR_T
bool Transcoder::equals(const wchar_t* str1, size_t len, const LogString& str2) {
    if (len == str2.length()) {
        LogString decoded;
        decode(str1, len, decoded);
        return decoded == str2;
    }
    return false;
}
#endif


/**
*   Appends an external string to an
*     internal string.
*/
void Transcoder::decode(const char* src, size_t len, LogString& dst) {
  static CharsetDecoderPtr decoder(CharsetDecoder::getDefaultDecoder());
  if (len > 0) {
    ByteBuffer buf((char*) src, len);
    while(buf.remaining() > 0) {
      log4cxx_status_t stat = decoder->decode(buf, dst);
      if(CharsetDecoder::isError(stat)) {
        dst.append(1, LOG4CXX_STR('?'));
        buf.position(buf.position() + 1);
      }
    }
    decoder->decode(buf, dst);
  }
}

void Transcoder::encode(const LogString& src, std::string& dst) {
  static CharsetEncoderPtr encoder(CharsetEncoder::getDefaultEncoder());
  if (src.length() > 0) {
    char buf[BUFSIZE];
    ByteBuffer out(buf, BUFSIZE);
    LogString::const_iterator iter = src.begin();
    while(iter != src.end()) {
      log4cxx_status_t stat = encoder->encode(src, iter, out);
      out.flip();
      dst.append(out.data(), out.limit());
      out.clear();
      if (CharsetEncoder::isError(stat)) {
        //
        //  represent character with an escape sequence
        //
        dst.append("\\u");
        const char* hexdigits = "0123456789ABCDEF";
        unsigned short unencodable = *iter;
        dst.append(1, hexdigits[(unencodable >> 12) & 0x0F]);
        dst.append(1, hexdigits[(unencodable >> 8) & 0x0F]);
        dst.append(1, hexdigits[(unencodable >> 4) & 0x0F]);
        dst.append(1, hexdigits[unencodable & 0x0F]);
        iter++;
      }
    }
    encoder->encode(src, iter, out);
  }
}


#if LOG4CXX_LOGCHAR_IS_WCHAR
void Transcoder::decode(const wchar_t* src, size_t len, LogString& dst) {
  dst.append(src, len);
}

void Transcoder::encode(const LogString& src, std::wstring& dst) {
  dst.append(src);
}
#else
#if LOG4CXX_HAS_WCHAR_T
void Transcoder::decode(const wchar_t* src, size_t len, LogString& dst) {
  static CharsetDecoderPtr encoder(CharsetDecoder::getWideDecoder());
  if (len > 0) {
    ByteBuffer buf((char*) src, len * sizeof(wchar_t));
    while(buf.remaining() > 0) {
      log4cxx_status_t stat = decoder->decode(buf, dst);
      if(CharsetDecoder::isError(stat)) {
        dst.append(1, LOG4CXX_STR('?'));
        buf.position(buf.position() + sizeof(wchar_t));
      }
    }
    decoder->decode(buf, dst);
  }
}

void Transcoder::encode(const LogString& src, std::wstring& dst) {
  static CharsetEncoderPtr encoder(CharsetEncoder::getWideEncoder());
  if (src.length() > 0) {
    char buf[BUFSIZE];
    ByteBuffer out(buf, BUFSIZE);
    LogString::const_iterator iter = src.begin();
    for(iter != src.end()) {
      log4cxx_status_t stat = encoder->encode(src, iter, out);
      out.flip();
      dst.append(out.data(), out.limit());
      out.clear();
      if (CharsetEncoder::isError(stat)) {
        //
        //  represent character with an escape sequence
        //
        dst.append("\\u");
        const char* hexdigits = "0123456789ABCDEF";
        unsigned short unencodable = *iter;
        dst.append(1, hexdigits[(unencodable >> 12) & 0x0F]);
        dst.append(1, hexdigits[(unencodable >> 8) & 0x0F]);
        dst.append(1, hexdigits[(unencodable >> 4) & 0x0F]);
        dst.append(1, hexdigits[unencodable & 0x0F]);
        iter++;
      }
    }
    encoder->encode(src, iter, out);
  }
}
#endif
#endif




