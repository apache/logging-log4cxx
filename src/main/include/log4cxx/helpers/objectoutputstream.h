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

#ifndef _LOG4CXX_HELPERS_OBJECTOUTPUTSTREAM_H
#define _LOG4CXX_HELPERS_OBJECTOUTPUTSTREAM_H

#include <log4cxx/helpers/objectimpl.h>
#include <map>

namespace log4cxx
{

        namespace helpers {
          class OutputStream;
          typedef helpers::ObjectPtrT<OutputStream> OutputStreamPtr;
          class ByteBuffer;
          class CharsetEncoder;
          typedef helpers::ObjectPtrT<CharsetEncoder> CharsetEncoderPtr;

          /**
          *  Emulates java serialization.
          */
          class LOG4CXX_EXPORT ObjectOutputStream : public ObjectImpl
          {
          public:
                  DECLARE_ABSTRACT_LOG4CXX_OBJECT(ObjectOutputStream)
                  BEGIN_LOG4CXX_CAST_MAP()
                          LOG4CXX_CAST_ENTRY(ObjectOutputStream)
                  END_LOG4CXX_CAST_MAP()

                  ObjectOutputStream(OutputStreamPtr os, Pool& p);
                  virtual ~ObjectOutputStream();

                  void close(Pool& p);
                  void writeUTF(const LogString&, Pool& p);
                  void writeObject(const LogString&, Pool& p);
                  void writeObject(const std::map<LogString, LogString>& mdc, Pool& p);
                  void writeInt(int val, Pool& p);
                  void writeLong(log4cxx_time_t val, Pool& p);
                  void writeByte(char val, Pool& p);
                  void writeBytes(const char* bytes, size_t len, Pool& p);

                  enum { STREAM_MAGIC = 0xACED };
                  enum { STREAM_VERSION = 5 };
                  enum { TC_NULL = 0x70,
                         TC_REFERENCE = 0x71,
                         TC_CLASSDESC = 0x72,
                         TC_OBJECT = 0x73,
                         TC_STRING = 0x74,
                         TC_ARRAY = 0x75,
                         TC_CLASS = 0x76,
                         TC_BLOCKDATA = 0x77,
                         TC_ENDBLOCKDATA = 0x78 };
                 enum {
                     SC_WRITE_METHOD = 0x01,
                     SC_SERIALIZABLE = 0x02 };

          private:
                  ObjectOutputStream(const ObjectOutputStream&);
                  ObjectOutputStream& operator=(const ObjectOutputStream&);
                     
                  OutputStreamPtr os;
#if !LOG4CXX_LOGCHAR_IS_UTF8
                  log4cxx::helpers::CharsetEncoderPtr utf8Encoder;
#endif                 
          };

        } // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_OUTPUTSTREAM_H

