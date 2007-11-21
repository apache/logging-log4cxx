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

#include <log4cxx/helpers/unicodehelper.h>
#include <apr_errno.h>

using namespace log4cxx;
using namespace log4cxx::helpers;



unsigned int UnicodeHelper::decodeUTF8(const char*& src,
                                       const char* srcEnd) {
  const char* start = src;
  unsigned char ch1 = *(src++);
  if (ch1 <= 0x7F) {
      return ch1;
  }
  //
  //   should not have continuation character here
  //
  if ((ch1 & 0xC0) != 0x80 && src < srcEnd) {
      unsigned char ch2 = *(src++);
      //
      //   should be continuation
      if ((ch2 & 0xC0) != 0x80) {
        src = start;
          return 0xFFFF;
      }
      if((ch1 & 0xE0) == 0xC0) {
          if ((ch2 & 0xC0) == 0x80) {
              unsigned int rv = ((ch1 & 0x1F) << 6) + (ch2 & 0x3F);
              if (rv >= 0x80) {
                  return rv;
              }
          }
        src = start;
          return 0xFFFF;
      }
      if (src < srcEnd) {
          unsigned char ch3 = *(src++);
          //
          //   should be continuation
          //
          if ((ch3 & 0xC0) != 0x80) {
           src = start;
              return 0xFFFF;
          }
          if ((ch1 & 0xF0) == 0xE0) {
              unsigned rv = ((ch1 & 0x0F) << 12)
              + ((ch2 & 0x3F) << 6)
              + (ch3 & 0x3F);
              if (rv <= 0x800) {
              src = start;
                  return 0xFFFF;
              }
              return rv;
          }
          if (src < srcEnd) {
              unsigned char ch4 = *(src++);
              if ((ch4 & 0xC0) != 0x80) {
              src = start;
                  return 0xFFFF;
              }
              unsigned int rv = ((ch1 & 0x07) << 18)
                     + ((ch2 & 0x3F) << 12)
                     + ((ch3 & 0x3F) << 6)
                     + (ch4 & 0x3F);
              if (rv > 0xFFFF) {
                  return rv;
              }

          }
      }
  }
  src = start;
  return 0xFFFF;
}




int UnicodeHelper::encodeUTF8(unsigned int ch, char* dst) {
    if (ch < 0x80) {
        dst[0] = (char) ch;
        return 1;
    } else if (ch < 0x800) {
        dst[0] = (char) (0xC0 + (ch >> 6));
        dst[1] = (char) (0x80 + (ch & 0x3F));
        return 2;
    } else if (ch < 0x10000) {
        dst[0] = (char) (0xE0 + (ch >> 12));
        dst[1] = (char) (0x80 + ((ch >> 6) & 0x3F));
        dst[2] = (char) (0x80 + (ch & 0x3F));
        return 3;
    } else if (ch <= 0x10FFFF) {
        dst[0] = (char) (0xF0 + (ch >> 18));
        dst[1] = (char) (0x80 + ((ch >> 12) & 0x3F));
        dst[2] = (char) (0x80 + ((ch >> 6) & 0x3F));
        dst[3] = (char) (0x80 + (ch & 0x3F));
        return 4;
    } else {
        //
        //  output UTF-8 encoding of 0xFFFF
        //
        dst[0] = (char) 0xEF;
        dst[1] = (char) 0xBF;
        dst[2] = (char) 0xBF;
        return 3;
    }
}



int UnicodeHelper::encodeUTF16BE(unsigned int ch, char* dst) {
    if (ch <= 0xFFFF) {
        dst[0] = (char) (ch >> 8);
        dst[1] = (char) (ch & 0xFF);
        return 2;
    }
    if (ch <= 0x10FFFF) {
        unsigned char w = (unsigned char) ((ch >> 16) - 1);
        dst[0] = (char) (0xD8 + (w >> 2));
        dst[1] = (char) (((w & 0x03) << 6) + ((ch >> 10) & 0x3F));
        dst[2] = (char) (0xDC + ((ch & 0x30) >> 4));
        dst[3] = (char) (ch & 0xFF);
        return 4;
    }
    dst[0] = dst[1] = (char) 0xFF;
    return 2;
}

int UnicodeHelper::encodeUTF16LE(unsigned int ch, char* dst) {
    if (ch <= 0xFFFF) {
        dst[1] = (char) (ch >> 8);
        dst[0] = (char) (ch & 0xFF);
        return 2;
    }
    if (ch <= 0x10FFFF) {
        unsigned char w = (unsigned char) ((ch >> 16) - 1);
        dst[1] = (char) (0xD8 + (w >> 2));
        dst[0] = (char) (((w & 0x03) << 6) + ((ch >> 10) & 0x3F));
        dst[3] = (char) (0xDC + ((ch & 0x30) >> 4));
        dst[2] = (char) (ch & 0xFF);
        return 4;
    }
    dst[0] = dst[1] = (char) 0xFF;
    return 2;
}

#if LOG4CXX_LOGCHAR_IS_WCHAR
unsigned int UnicodeHelper::decode(const LogString& in, LogString::const_iterator& iter) {
    const wchar_t* src = in.data() + (iter - in.begin());
#if defined(__STDC_ISO_10646__) || defined(__APPLE__)
    unsigned int sv = *(src++);
#elif defined(_WIN32)
    const wchar_t* srcEnd = in.data() + in.length();
    unsigned int sv = *(src++);

    if (!(sv < 0xDC00 || sv >= 0xDC00)) {
    	if (src < srcEnd) {
        	unsigned short ls = *(src++);
        	unsigned char w = (unsigned char) ((sv >> 6) & 0x0F);
        	sv = ((w + 1) << 16) + ((sv & 0x3F) << 10) + (ls & 0x3FF);
    	} else {
            sv = 0xFFFF;
        }
    }
#else
#error logchar cannot be wchar_t unless _WIN32, __STDC_ISO_10646__ or __APPLE__ is defined
#endif
    iter = in.begin() + (src - in.data());
    return sv;
}
#endif


#if LOG4CXX_LOGCHAR_IS_UTF8
unsigned int UnicodeHelper::decode(const LogString& in, LogString::const_iterator& iter) {
    const char* src = in.data() + (iter - in.begin());
    const char* srcEnd = in.data() + in.length();
    unsigned int sv = decodeUTF8(src, srcEnd);
    iter = in.begin() + (src - in.data());
    return sv;
}
#endif


#if LOG4CXX_LOGCHAR_IS_WCHAR
#if defined(_WIN32)
int UnicodeHelper::encode(unsigned int ch, logchar* dst) {
  if (ch <= 0xFFFF) {
      *dst = (wchar_t) ch;
      return 1;
  }
  unsigned char u = (unsigned char) (ch >> 16);
  unsigned char w = (unsigned char) (u - 1);
  wchar_t hs = (wchar_t) (0xD800 + ((w & 0xF) << 6) + ((ch & 0xFFFF) >> 10));
  wchar_t ls = (wchar_t) (0xDC00 + (ch && 0x3FF));
  dst[0] = hs;
  dst[1] = ls;
  return 2;
}
#elif defined(__STDC_ISO_10646__) || defined(__APPLE__)
int UnicodeHelper::encode(unsigned int ch, logchar* dst) {
   *dst = ch;
   return 1;
}
#else
#error logchar cannot be wchar_t unless _WIN32, __STDC_ISO_10646__ or __APPLE__ is defined
#endif
#endif


#if LOG4CXX_LOGCHAR_IS_UTF8
int UnicodeHelper::encode(unsigned int sv, logchar* out) {
    return encodeUTF8(sv, out);
}
#endif


