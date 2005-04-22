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


namespace log4cxx
{
        namespace helpers {

#if !defined(_WIN32)
          /**
           *  Converts from an arbitrary encoding to LogString
           *    using apr_xlate.
           */
          class APRCharsetDecoder : public CharsetDecoder
          {
          public:
              APRCharsetDecoder(const char* frompage) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
                const char* topage = "WCHAR_T";
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
                const char* topage = "UTF-8";
#endif
                apr_status_t stat = apr_pool_create(&pool, NULL);
                if (stat != APR_SUCCESS) {
                    throw PoolException(stat);
                }
                stat = apr_xlate_open(&convset,
                    topage,
                    frompage,
                    pool);
                if (stat != APR_SUCCESS) {
                    throw IllegalArgumentException(topage);
                }
              }

              virtual ~APRCharsetDecoder() {
                apr_xlate_close(convset);
                apr_pool_destroy(pool);
              }

              virtual log4cxx_status_t decode(ByteBuffer& in,
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

          private:
                  APRCharsetDecoder(const APRCharsetDecoder&);
                  APRCharsetDecoder& operator=(const APRCharsetDecoder&);
                  apr_pool_t* pool;
                  apr_xlate_t *convset;
          };
#endif


#if LOG4CXX_HAS_WCHAR_T || defined(_WIN32)
          /**
          *    Converts from the default multi-byte string to
          *        LogString using mbstowcs.
          *
          */
          class MbstowcsCharsetDecoder : public CharsetDecoder
          {
          public:
              MbstowcsCharsetDecoder() {
              }

              virtual ~MbstowcsCharsetDecoder() {
              }

              virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  enum { BUFSIZE = 256 };
                  wchar_t buf[BUFSIZE];

                  while(in.remaining() > 0) {
                      size_t requested = in.remaining();
                      if (requested > BUFSIZE - 1) {
                          requested = BUFSIZE - 1;
                      }

                      for(; requested > 0; requested--) {
                        memset(buf, 0, BUFSIZE*sizeof(wchar_t));
                        size_t converted = mbstowcs(buf, in.data() + in.position(), requested);
                        if (converted != (size_t) -1) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
                            out.append(buf);
#else
                            size_t wlen = wcslen(buf);
                            out.reserve(out.length() + wlen);
                            for(int i = 0; i < wlen; i++) {
                                encodeUTF8(buf[i], out);
                            }
#endif
                            in.position(in.position() + converted);
                            break;
                        }
                      }
                      if (requested == 0) {
                          return APR_BADARG;
                      }
                  }
                  return APR_SUCCESS;
              }


              static void encodeUTF8(unsigned short ch, std::string& out) {
                  if (ch <= 0x7F) {
                      out.append(1, (char) ch);
                  } else {
                      //
                      //   TODO
                      //
                      out.append(1, '?');
                  }
              }



          private:
                  MbstowcsCharsetDecoder(const MbstowcsCharsetDecoder&);
                  MbstowcsCharsetDecoder& operator=(const MbstowcsCharsetDecoder&);
          };
#endif


#if LOG4CXX_LOGCHAR_IS_WCHAR
          /**
          *    Converts from the default multi-byte string to
          *        LogString using mbstowcs.
          *
          */
          class TrivialWideCharsetDecoder : public CharsetDecoder
          {
          public:
              TrivialWideCharsetDecoder() {
              }

              virtual ~TrivialWideCharsetDecoder() {
              }

              virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  const wchar_t* src = (const wchar_t*) (in.data() + in.position());
                  size_t remaining = in.remaining();
                  size_t count = remaining / sizeof(wchar_t);
                  out.append(src, count);
                  in.position(in.position() + count * sizeof(wchar_t));
                  if (remaining & 1) {
                      return APR_BADARG;
                  }
                  return APR_SUCCESS;
              }



          private:
                  TrivialWideCharsetDecoder(const TrivialWideCharsetDecoder&);
                  TrivialWideCharsetDecoder& operator=(const TrivialWideCharsetDecoder&);
          };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8 && defined(_WIN32)
          /**
          *    Converts from the default multi-byte string to
          *        UTF-8 std::string
          *
          */
          class WideToUTF8CharsetDecoder : public CharsetDecoder
          {
          public:
              WideToUTF8CharsetDecoder() {
              }

              virtual ~WideToUTF8CharsetDecoder() {
              }

              virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  const wchar_t* src = in.data() + in.position();
                  size_t remaining = in.remaining();
                  size_t count = remaining / sizeof(wchar_t);
                  out.reserve(out.length() + count;
                  for(int i = 0; i < count; i++, src++) {
                      MbstowcsCharsetDecoder::encodeUTF8(*src, out);
                  }
                  in.position(in.position() + count * sizeof(wchar_t));
                  if (remaining & 1) {
                      return APR_BADARG;
                  }
                  return APR_SUCCESS;
              }



          private:
                  WideToUTF8CharsetDecoder(const WideToUTF8CharsetDecoder&);
                  WideToUTF8CharsetDecoder& operator=(const WideToUTF8CharsetDecoder&);
          };
#endif


        } // namespace helpers

}  //namespace log4cxx


CharsetDecoder::CharsetDecoder() {
}


CharsetDecoder::~CharsetDecoder() {
}

CharsetDecoderPtr CharsetDecoder::getDefaultDecoder() {
#if LOG4CXX_HAS_WCHAR_T || defined(_WIN32)
    static CharsetDecoderPtr decoder(new MbstowcsCharsetDecoder());
#else
    static CharsetDecoderPtr decoder(new APRCharsetDecoder(APR_LOCALE_CHARSET));
#endif
    return decoder;
}

#if LOG4CXX_HAS_WCHAR_T
CharsetDecoderPtr CharsetDecoder::getWideDecoder() {
#if LOG4CXX_LOGCHAR_IS_WCHAR
  static CharsetDecoderPtr decoder(new TrivialWideCharsetDecoder());
#elif defined(_WIN32)
  static CharsetDecoderPtr decoder(new WideToUTF8CharsetDecoder());
#else
  static CharsetDecoderPtr decoder(new APRCharsetDecoder("WCHAR_T"));
#endif
  return decoder;
}
#endif

