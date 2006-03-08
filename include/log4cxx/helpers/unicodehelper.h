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

#ifndef _LOG4CXX_HELPERS_UNICODEHELPER_H
#define _LOG4CXX_HELPERS_UNICODEHELPER_H

#include <string>
#include <log4cxx/logstring.h>

namespace log4cxx {
    namespace helpers {
          /**
           *   UnicodeHelper provides static methods for encoding and decoding
         *   UTF-8, UTF-16 and wchar_t from UCS-4 values.
           *
           */
          class UnicodeHelper {
          private:
              /**
               * Inaccessible constructor.
               */
              UnicodeHelper() {
              }

          public:
              /**
               *   Decodes next character from a sequence of UTF-8 bytes.
               *   @param src start of character, will be modified to point at next character.
               *   @param srcEnd end of sequence.
               *   @return scalar value (UCS-4) or 0xFFFF if invalid sequence.
               */
              static unsigned int decodeUTF8(const char*& src,
                  const char* srcEnd);


              /**
               *   Encodes a character using UTF-8.
               *   @param ch UCS-4 value.
               *   @param dst buffer to receive UTF-8 encoding (must be at least 8 bytes)
               *   @return number of bytes needed to represent character
               */
              static int encodeUTF8(unsigned int ch, char* dst);

              /**
               *   Encodes a character using UTF-16BE.
               *   @param ch UCS-4 value.
               *   @param dst buffer to receive UTF-16BE encoding (must be at least 4 bytes)
               *   @return number of bytes needed to represent character
               */
              static int encodeUTF16BE(unsigned int ch, char* dst);

              /**
               *   Encodes a character using UTF-16LE.
               *   @param ch UCS-4 value.
               *   @param dst buffer to receive UTF-16BE encoding (must be at least 4 bytes)
               *   @return number of bytes needed to represent character
               */
              static int encodeUTF16LE(unsigned int ch, char* dst);


#if LOG4CXX_HAS_WCHAR_T
              /**
               *   Decodes next character from a sequence of wchar_t values.
               *   @param src start of character, will be modified to point at next character.
               *   @param srcEnd end of sequence.
               *   @return scalar value (UCS-4) or 0xFFFF if invalid sequence.
               */
              static unsigned int decodeWide(const wchar_t*& src, const wchar_t* srcEnd);


              /**
               *   Encodes a character to wchar_t.
               *   @param ch UCS-4 value.
               *   @param dst buffer to receive wchar_t (must be at least 2 wchar_t)
               *   @return number of wchar_t needed to represent character
               */
              static int encodeWide(unsigned int ch, wchar_t* str);

           /**
            *   Determines the number of UTF-8 bytes required to express
            *   the wchar_t value.
            *   @param ch wchar_t value
            *   @return number of bytes required.
            */
              static int lengthUTF8(wchar_t ch);

#endif

              /**
               *   Decodes next character from a LogString.
               *   @param in string from which the character is extracted.
               *   @param iter iterator addressing start of character, will be
            *   advanced to next character if successful.
               *   @return scalar value (UCS-4) or 0xFFFF if invalid sequence.
               */
              static unsigned int decode(const LogString& in,
                  LogString::const_iterator& iter);

              /**
               *   Encodes a UCS-4 value to logchar.
               *   @param ch UCS-4 value.
               *   @param dst buffer to receive logchar encoding (must be at least 8)
               *   @return number of logchar needed to represent character
               */
              static int encode(unsigned int ch, logchar* dst);

          };
    }
}
#endif
