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

#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/exception.h>
#include <apr_xlate.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(CharsetDecoder)


CharsetDecoder::CharsetDecoder(const char* frompage) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
  const char* topage = "WCHAR_T";
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
  const char* topage = "UTF-8";
#endif
  apr_status_t stat = apr_xlate_open((apr_xlate_t**) &convset,
     topage,
     frompage,
     (apr_pool_t*) pool.getAPRPool());
  if (stat != APR_SUCCESS) {
    throw IllegalArgumentException(topage);
  }
}

CharsetDecoder::~CharsetDecoder() {
  apr_xlate_close((apr_xlate_t*) convset);
}

CharsetDecoderPtr CharsetDecoder::getDefaultDecoder() {
  static CharsetDecoderPtr decoder(new CharsetDecoder(APR_LOCALE_CHARSET));
  return decoder;
}

CharsetDecoderPtr CharsetDecoder::getWideDecoder() {
  static CharsetDecoderPtr decoder(new CharsetDecoder("WCHAR_T"));
  return decoder;
}

CharsetDecoderPtr CharsetDecoder::getDecoder(const LogString& charset) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
   std::string cs(charset.size(), ' ');
   for(int i = 0; i < charset.size(); i++) {
      cs[i] = (char) charset[i];
   }
   return new CharsetDecoder(cs.c_str());
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
   return new CharsetDecoder(charset.c_str());
#endif
}


log4cxx_status_t CharsetDecoder::decode(
      ByteBuffer& in,
      LogString& out) {
      enum { BUFSIZE = 256 };
      logchar buf[BUFSIZE];
      const apr_size_t initial_outbytes_left = BUFSIZE * sizeof(logchar);
      apr_status_t stat = APR_SUCCESS;
      if (in.remaining() == 0) {
        size_t outbytes_left = initial_outbytes_left;
        stat = apr_xlate_conv_buffer((apr_xlate_t*) convset,
            NULL, NULL, (char*) buf, &outbytes_left);
        out.append(buf, (initial_outbytes_left - outbytes_left)/sizeof(logchar));
      } else {
        while(in.remaining() > 0 && stat == APR_SUCCESS) {
          size_t inbytes_left = in.remaining();
          size_t initial_inbytes_left = inbytes_left;
          size_t pos = in.position();
          apr_size_t outbytes_left = initial_outbytes_left;
          stat = apr_xlate_conv_buffer((apr_xlate_t*) convset,
               in.data() + pos,
               &inbytes_left,
               (char*) buf,
               &outbytes_left);
          out.append(buf, (initial_outbytes_left - outbytes_left)/sizeof(logchar));
          in.position(pos + (initial_inbytes_left - inbytes_left));
        }
      }
      return stat;
}



