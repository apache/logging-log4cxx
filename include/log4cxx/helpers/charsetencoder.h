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

#ifndef _LOG4CXX_HELPERS_CHARSETENCODER_H
#define _LOG4CXX_HELPERS_CHARSETENCODER_H

#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/pool.h>

namespace log4cxx
{

        namespace helpers {
          class CharsetEncoder;
          typedef helpers::ObjectPtrT<CharsetEncoder> CharsetEncoderPtr;
          class ByteBuffer;


          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
          */
          class LOG4CXX_EXPORT CharsetEncoder : public ObjectImpl
          {
          public:
                  DECLARE_ABSTRACT_LOG4CXX_OBJECT(CharsetEncoder)
                  BEGIN_LOG4CXX_CAST_MAP()
                          LOG4CXX_CAST_ENTRY(CharsetEncoder)
                  END_LOG4CXX_CAST_MAP()

          private:
                  CharsetEncoder(const char* topage);
                  virtual ~CharsetEncoder();

          public:
                  static CharsetEncoderPtr getDefaultEncoder();
                  static CharsetEncoderPtr getWideEncoder();
                  static CharsetEncoderPtr getEncoder(const LogString& charset);

                  /**
                  * Encodes a string replacing unmappable
                  * characters with escape sequences.
                  *
                  */
                  static void encode(CharsetEncoderPtr& enc,
                      const LogString& src,
                      LogString::const_iterator& iter,
                      ByteBuffer& dst);

                  virtual log4cxx_status_t encode(const LogString& in,
                        LogString::const_iterator& iter,
                        ByteBuffer& out);

                  virtual void reset();

                  virtual void flush(ByteBuffer& out);

                  inline static bool isError(log4cxx_status_t stat) {
                     return (stat != 0);
                  }


          private:
                  CharsetEncoder(const CharsetEncoder&);
                  CharsetEncoder& operator=(const CharsetEncoder&);
                  Pool pool;
                  void *convset;
          };

        } // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_CHARSETENCODER_H
