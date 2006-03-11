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

#ifndef _LOG4CXX_HELPERS_INPUTSTREAM_H
#define _LOG4CXX_HELPERS_INPUTSTREAM_H

#include <log4cxx/helpers/objectimpl.h>

namespace log4cxx
{

        namespace helpers {
          class ByteBuffer;

          /**
           * Abstract class for reading from character streams.
           * @since 0.9.8
           */
          class LOG4CXX_EXPORT InputStream : public ObjectImpl
          {
          public:
                  DECLARE_ABSTRACT_LOG4CXX_OBJECT(InputStream)
                  BEGIN_LOG4CXX_CAST_MAP()
                          LOG4CXX_CAST_ENTRY(InputStream)
                  END_LOG4CXX_CAST_MAP()

          protected:
                  InputStream();

                  virtual ~InputStream();

          public:
                  /**
                   * Reads up to len bytes of data from this input stream 
                   * into an array of chars.
                   *
                   * @param b   The buffer into which the data is read.
                   * @param off The start offset of the data.
                   * @param len The maximum number of bytes to read.
                   * @return the total number of bytes read into the buffer, or -1 if there
                   *         is no more data because the end of the stream has been reached.
                   */
                  virtual int read(char* buf, int off, int len) const = 0;

                  /**
                   * Closes this input stream and releases any system 
                   * resources associated with the stream.
                   */
                  virtual void close() = 0;

          private:
                  InputStream(const InputStream&);
                  InputStream& operator=(const InputStream&);
          };

          typedef helpers::ObjectPtrT<InputStream> InputStreamPtr;
        } // namespace helpers

}  //namespace log4cxx

#endif //_LOG4CXX_HELPERS_INPUTSTREAM_H
