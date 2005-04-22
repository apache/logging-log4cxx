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

#ifndef _LOG4CXX_HELPERS_CHARSETDECODER_H
#define _LOG4CXX_HELPERS_CHARSETDECODER_H

#include <log4cxx/helpers/objectimpl.h>

namespace log4cxx
{
        namespace helpers {
          class CharsetDecoder;
          typedef helpers::ObjectPtrT<CharsetDecoder> CharsetDecoderPtr;
          class ByteBuffer;


          /**
          *   An engine to transform a byte array in
          *     a character set to LogStrings.
          */
          class LOG4CXX_EXPORT CharsetDecoder : public ObjectImpl
          {
          public:
                  DECLARE_ABSTRACT_LOG4CXX_OBJECT(CharsetDecoder)
                  BEGIN_LOG4CXX_CAST_MAP()
                          LOG4CXX_CAST_ENTRY(CharsetDecoder)
                  END_LOG4CXX_CAST_MAP()
          protected:
                  CharsetDecoder();
          public:
                  virtual ~CharsetDecoder();
                  static CharsetDecoderPtr getDefaultDecoder();
#if LOG4CXX_HAS_WCHAR_T
                  static CharsetDecoderPtr getWideDecoder();
#endif

                  virtual log4cxx_status_t decode(ByteBuffer& in,
                        LogString& out) = 0;

                  inline static bool isError(log4cxx_status_t stat) {
                     return (stat != 0);
                  }

          private:
                  CharsetDecoder(const CharsetDecoder&);
                  CharsetDecoder& operator=(const CharsetDecoder&);
          };

        } // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_CHARSETENCODER_H
