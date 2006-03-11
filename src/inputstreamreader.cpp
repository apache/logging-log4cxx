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

InputStreamReader::InputStreamReader(InputStreamPtr& in)
   : in(in), dec(CharsetDecoder::getDefaultDecoder()) {
   if (in == 0) {
      throw NullPointerException("in parameter may not be null.");
   }
}

InputStreamReader::InputStreamReader(InputStreamPtr& in, CharsetDecoderPtr &dec) 
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
    char* buf = p.palloc(BUFSIZE);
    char* contents = buf;
    int contentLength = 0;
    int bytesRead = 0;

    // read whole file
    do {
      bytesRead = in->read(buf, 0, BUFSIZE);
      if (bytesRead > 0) {
        contentLength += bytesRead;
      }
      if (bytesRead < BUFSIZE) {
        bytesRead = -1;
      }

      if (bytesRead != -1) {
         //
         //   file was larger than the buffer
         //      realloc a bigger buffer
         char* newContents = p.palloc(contentLength + BUFSIZE);
         buf = newContents + contentLength;
         memcpy(newContents, contents, contentLength);
         //
         //   we would free contents here if you did that sort of thing
         //
         contents = newContents;
      }
    } while(bytesRead != -1);

    //
    //     finished file
    //        transcode and exit
    LogString output;
    ByteBuffer input(contents, contentLength);
    dec->decode(input, output);
    return output;
}
