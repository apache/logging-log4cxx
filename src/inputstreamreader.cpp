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

#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/inputstreamreader.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/bytebuffer.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(InputStreamReader)

InputStreamReader::InputStreamReader(const InputStreamPtr& in)
   : in(in), dec(CharsetDecoder::getDefaultDecoder()) {
   if (in == 0) {
      throw NullPointerException("in parameter may not be null.");
   }
}

InputStreamReader::InputStreamReader(const InputStreamPtr& in, const CharsetDecoderPtr &dec) 
    : in(in), dec(dec) {
    if (in == 0) {
       throw NullPointerException("in parameter may not be null.");
    }
    if (dec == 0) {
       throw NullPointerException("dec parameter may not be null.");
    }
}

InputStreamReader::~InputStreamReader() {
}

void InputStreamReader::close(Pool& ) {
  in->close();
}

LogString InputStreamReader::read(Pool& p) {
    const size_t BUFSIZE = 4096;
    ByteBuffer buf(p.palloc(BUFSIZE), BUFSIZE);
    LogString output;

    // read whole file
    while(in->read(buf) >= 0) {
         buf.flip();
         log4cxx_status_t stat = dec->decode(buf, output);
         if (stat != 0) {
             throw IOException(stat);
         }
         if (buf.remaining() > 0) {
             memmove(buf.data(), buf.current(), buf.remaining());
             buf.limit(buf.remaining());
         } else {
             buf.clear();
         }
    }

    return output;
}
