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

#include <log4cxx/helpers/charsetencoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/exception.h>
#include <apr_xlate.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(CharsetEncoder)


CharsetEncoder::CharsetEncoder(const char* topage) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
  const char* frompage = "WCHAR_T";
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
  const char* frompage = "UTF-8";
#endif
  apr_status_t stat = apr_xlate_open((apr_xlate_t**) &convset,
     topage,
     frompage,
     (apr_pool_t*) pool.getAPRPool());
  if (stat != APR_SUCCESS) {
    throw IllegalArgumentException(topage);
  }
}

CharsetEncoder::~CharsetEncoder() {
  apr_xlate_close((apr_xlate_t*) convset);
}

CharsetEncoderPtr CharsetEncoder::getDefaultEncoder() {
  static CharsetEncoderPtr encoder(new CharsetEncoder(APR_LOCALE_CHARSET));
  return encoder;
}

CharsetEncoderPtr CharsetEncoder::getWideEncoder() {
  static CharsetEncoderPtr encoder(new CharsetEncoder("WCHAR_T"));
  return encoder;
}

CharsetEncoderPtr CharsetEncoder::getEncoder(const LogString& charset) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
   std::string cs(charset.size(), ' ');
   for(int i = 0; i < charset.size(); i++) {
      cs[i] = (char) charset[i];
   }
   return new CharsetEncoder(cs.c_str());
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
   return new CharsetEncoder(charset.c_str());
#endif
}


log4cxx_status_t CharsetEncoder::encode(const LogString& in,
      LogString::const_iterator& iter,
      ByteBuffer& out) {
      apr_status_t stat;
      size_t outbytes_left = out.remaining();
      size_t initial_outbytes_left = outbytes_left;
      size_t position = out.position();
      if (iter == in.end()) {
        stat = apr_xlate_conv_buffer((apr_xlate_t*) convset, NULL, NULL,
           out.data() + position, &outbytes_left);
      } else {
        LogString::size_type inOffset = (iter - in.begin());
        apr_size_t inbytes_left =
            (in.size() - inOffset) * sizeof(LogString::value_type);
        apr_size_t initial_inbytes_left = inbytes_left;
        stat = apr_xlate_conv_buffer((apr_xlate_t*) convset,
             (const char*) (in.data() + inOffset),
             &inbytes_left,
             out.data() + position,
             &outbytes_left);
        iter += ((initial_inbytes_left - inbytes_left) / sizeof(LogString::value_type));
      }
      out.position(out.position() + (initial_outbytes_left - outbytes_left));
      return stat;
}


void CharsetEncoder::reset() {
}

void CharsetEncoder::flush(ByteBuffer& out) {
}




void CharsetEncoder::encode(CharsetEncoderPtr& enc,
    const LogString& src,
    LogString::const_iterator& iter,
    ByteBuffer& dst) {
    log4cxx_status_t stat = enc->encode(src, iter, dst);
    if (stat != APR_SUCCESS && iter != src.end()) {
      iter++;
      dst.put('?');
    }
}
