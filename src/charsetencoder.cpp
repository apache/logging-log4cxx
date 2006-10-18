/*
 * Copyright 2003,2006 The Apache Software Foundation.
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
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/charsetencoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/exception.h>
#include <apr_xlate.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/unicodehelper.h>


using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(CharsetEncoder)

namespace log4cxx
{

        namespace helpers {

#if APR_HAS_XLATE
          /**
          * A character encoder implemented using apr_xlate.
          */
          class APRCharsetEncoder : public CharsetEncoder
          {
          public:
              APRCharsetEncoder(const char* topage) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
                  const char* frompage = "WCHAR_T";
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
                  const char* frompage = "UTF-8";
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
                     if (topage == APR_DEFAULT_CHARSET) {
                         throw IllegalArgumentException("APR_DEFAULT_CHARSET");
                     else if (topage == APR_LOCALE_CHARSET) {
                         throw IllegalArgumentException("APR_LOCALE_CHARSET");
                     } else {
                         throw IllegalArgumentException(topage);
                     }
                  }
              }

              virtual ~APRCharsetEncoder() {
                    apr_xlate_close(convset);
                    apr_pool_destroy(pool);
              }

              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                      apr_status_t stat;
                      size_t outbytes_left = out.remaining();
                      size_t initial_outbytes_left = outbytes_left;
                      size_t position = out.position();
                      if (iter == in.end()) {
                        stat = apr_xlate_conv_buffer(convset, NULL, NULL,
                           out.data() + position, &outbytes_left);
                      } else {
                        LogString::size_type inOffset = (iter - in.begin());
                        apr_size_t inbytes_left =
                            (in.size() - inOffset) * sizeof(LogString::value_type);
                        apr_size_t initial_inbytes_left = inbytes_left;
                        stat = apr_xlate_conv_buffer(convset,
                             (const char*) (in.data() + inOffset),
                             &inbytes_left,
                             out.data() + position,
                             &outbytes_left);
                        iter += ((initial_inbytes_left - inbytes_left) / sizeof(LogString::value_type));
                      }
                      out.position(out.position() + (initial_outbytes_left - outbytes_left));
                      return stat;
              }

          private:
                  APRCharsetEncoder(const APRCharsetEncoder&);
                  APRCharsetEncoder& operator=(const APRCharsetEncoder&);
                  apr_pool_t* pool;
                  apr_xlate_t *convset;
          };
#endif

#if LOG4CXX_HAS_WCHAR_T
          /**
           *  A character encoder implemented using wcstombs.
          */
          class WcstombsCharsetEncoder : public CharsetEncoder
          {
          public:
              WcstombsCharsetEncoder() {
              }

           /**
            *   Converts a wchar_t to the default external multibyte encoding.
            */
              log4cxx_status_t encode(const std::wstring& in,
                  std::wstring::const_iterator& iter,
                    ByteBuffer& out) {
                      log4cxx_status_t stat = APR_SUCCESS;

                      if (iter != in.end()) {
                         size_t outbytes_left = out.remaining();
                         size_t position = out.position();
                         std::wstring::size_type inOffset = (iter - in.begin());
                         enum { BUFSIZE = 256 };
                         wchar_t buf[BUFSIZE];
                         size_t chunkSize = BUFSIZE - 1;
                         if (chunkSize * MB_LEN_MAX > outbytes_left) {
                             chunkSize = outbytes_left / MB_LEN_MAX;
                         }
                         if (chunkSize > in.length() - inOffset) {
                             chunkSize = in.length() - inOffset;
                         }
                         memset(buf, 0, BUFSIZE * sizeof(wchar_t));
                         memcpy(buf,
                             in.data() + inOffset,
                             chunkSize * sizeof(wchar_t));
                         size_t converted = wcstombs(out.data() + position, buf, outbytes_left);

                         if (converted == (size_t) -1) {
                             stat = APR_BADARG;
                             //
                             //   if unconvertable character was encountered
                             //       repeatedly halve source to get fragment that
                             //       can be converted
                             for(chunkSize /= 2;
                                 chunkSize > 0;
                                 chunkSize /= 2) {
                                 buf[chunkSize] = 0;
                                 converted = wcstombs(out.data() + position, buf, outbytes_left);
                                 if (converted != (size_t) -1) {
                                    iter += chunkSize;
                                    out.position(out.position() + converted);
                           break;
                                 }
                             }
                         } else {
                            iter += chunkSize;
                            out.position(out.position() + converted);
                         }
                      }
                      return stat;
              }

#if LOG4CXX_LOGCHAR_IS_UTF8
           /**
            *    Performs encoding by converting UTF-8 LogString into a wstring
            *      and delegating to the other encode method.
            */
              virtual log4cxx_status_t encode(const std::string& in,
                  std::string::const_iterator& iter,
                  ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  if (iter != in.end()) {
                    std::wstring wideIn;
                    wideIn.reserve(in.length());
                    const char* src = in.data() + (iter - in.begin());
                    const char* srcEnd = in.data() + in.length();
                    wchar_t tmp[2];
                    while(src < srcEnd) {
                        unsigned int sv = UnicodeHelper::decodeUTF8(src, srcEnd);
                        if (sv == 0xFFFF) {
                            iter = in.begin() + (src - in.data());
                            return APR_BADARG;
                        }

                        int wcharCount = UnicodeHelper::encodeWide(sv, tmp);
                        wideIn.append(tmp, wcharCount);
                    }
                    std::wstring::const_iterator wideIter(wideIn.begin());
                    stat = encode(wideIn, wideIter, out);
                    if (wideIter == wideIn.end()) {
                        iter = in.end();
                    } else {
                        for(std::wstring::const_iterator i = wideIn.begin();
                            i != wideIter;
                            i++) {
                            iter += UnicodeHelper::lengthUTF8(*i);
                        }
                    }
                  }
                  return stat;
              }
#endif


          private:
                  WcstombsCharsetEncoder(const WcstombsCharsetEncoder&);
                  WcstombsCharsetEncoder& operator=(const WcstombsCharsetEncoder&);
          };
#endif


          /**
          *   Encodes a LogString to US-ASCII.
          */
          class USASCIICharsetEncoder : public CharsetEncoder
          {
          public:
              USASCIICharsetEncoder() {
              }

              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  if (iter != in.end()) {
                      while(out.remaining() > 0 && iter != in.end()) {
                    LogString::const_iterator prev(iter);
                          unsigned int sv = UnicodeHelper::decode(in, iter);
                          if (sv <= 0x7F) {
                              out.put((char) sv);
                          } else {
                       iter = prev;
                              stat = APR_BADARG;
                              break;
                          }
                      }
                  }
                  return stat;
              }

          private:
                  USASCIICharsetEncoder(const USASCIICharsetEncoder&);
                  USASCIICharsetEncoder& operator=(const USASCIICharsetEncoder&);
          };

          /**
          *   Converts a LogString to ISO-8859-1.
          */
          class ISOLatinCharsetEncoder : public CharsetEncoder
          {
          public:
              ISOLatinCharsetEncoder() {
              }

              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  if (iter != in.end()) {
                      while(out.remaining() > 0 && iter != in.end()) {
                          LogString::const_iterator prev(iter);
                          unsigned int sv = UnicodeHelper::decode(in, iter);
                          if (sv <= 0xFF) {
                              out.put((char) sv);
                          } else {
                              iter = prev;
                              stat = APR_BADARG;
                              break;
                          }
                      }
                  }
                  return stat;
              }

          private:
                  ISOLatinCharsetEncoder(const ISOLatinCharsetEncoder&);
                  ISOLatinCharsetEncoder& operator=(const ISOLatinCharsetEncoder&);
          };

          /**
          *   Encodes a LogString to a byte array when the encodings are indentical.
          */
          class TrivialCharsetEncoder : public CharsetEncoder
          {
          public:
              TrivialCharsetEncoder() {
              }


              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  if(iter != in.end()) {
                 size_t requested = in.length() - (iter - in.begin());
                 if (requested > out.remaining()/sizeof(logchar)) {
                    requested = out.remaining()/sizeof(logchar);
                 }
                 memcpy(out.current(),
                       (const char*) in.data() + (iter - in.begin()),
                      requested * sizeof(logchar));
                 iter += requested;
                 out.position(out.position() + requested * sizeof(logchar));
              }
                  return APR_SUCCESS;
              }

          private:
                  TrivialCharsetEncoder(const TrivialCharsetEncoder&);
                  TrivialCharsetEncoder& operator=(const TrivialCharsetEncoder&);
          };

#if LOG4CXX_LOGCHAR_IS_UTF8
typedef TrivialCharsetEncoder UTF8CharsetEncoder;
#endif

#if LOG4CXX_LOGCHAR_IS_WCHAR
          /**
         *  Converts a wstring to UTF-8.
          */
          class UTF8CharsetEncoder : public CharsetEncoder
          {
          public:
              UTF8CharsetEncoder() {
              }

              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
              log4cxx_status_t stat = APR_SUCCESS;
                  if (iter != in.end()) {
                      const logchar* const srcBase = in.data();
                      const logchar* const srcEnd = srcBase + in.length();
                      const logchar* src = in.data() + (iter - in.begin());
                      while(out.remaining() >= 8 && src < srcEnd) {
                           unsigned int sv = UnicodeHelper::decodeWide(src, srcEnd);
                           if (sv == 0xFFFF) {
                               stat = APR_BADARG;
                        break;
                           }
                           int bytes = UnicodeHelper::encodeUTF8(sv, out.data() + out.position());
                           out.position(out.position() + bytes);
                      }
                 iter = in.begin() + (src - srcBase);
                  }
                  return APR_SUCCESS;
              }

          private:
                  UTF8CharsetEncoder(const UTF8CharsetEncoder&);
                  UTF8CharsetEncoder& operator=(const UTF8CharsetEncoder&);
          };
#endif


          /**
          *   Encodes a LogString to UTF16-BE.
          */
          class UTF16BECharsetEncoder : public CharsetEncoder
          {
          public:
              UTF16BECharsetEncoder() {
              }

              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  while(iter != in.end() && out.remaining() >= 4) {
                      unsigned int sv = UnicodeHelper::decode(in, iter);
                      if (sv == 0xFFFF) {
                          stat = APR_BADARG;
                          break;
                      }
                      int bytes = UnicodeHelper::encodeUTF16BE(sv, out.current());
                      out.position(out.position() + bytes);
                  }
                  return stat;
              }

          private:
                  UTF16BECharsetEncoder(const UTF16BECharsetEncoder&);
                  UTF16BECharsetEncoder& operator=(const UTF16BECharsetEncoder&);
          };

          /**
          *   Encodes a LogString to UTF16-LE.
          */
          class UTF16LECharsetEncoder : public CharsetEncoder
          {
          public:
              UTF16LECharsetEncoder() {
              }


              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  while(iter != in.end() && out.remaining() >= 4) {
                      unsigned int sv = UnicodeHelper::decode(in, iter);
                      if (sv == 0xFFFF) {
                          stat = APR_BADARG;
                          break;
                      }
                      int bytes = UnicodeHelper::encodeUTF16LE(sv, out.current());
                      out.position(out.position() + bytes);
                  }
                  return stat;
              }

          private:
                  UTF16LECharsetEncoder(const UTF16LECharsetEncoder&);
                  UTF16LECharsetEncoder& operator=(const UTF16LECharsetEncoder&);
          };

#if LOG4CXX_HAS_WCHAR_T
          /**
          *   Converts a LogString to an array of wchar_t.
          */
          class WideCharsetEncoder : public CharsetEncoder
          {
          public:
              WideCharsetEncoder() {
              }


              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  while(iter != in.end() && out.remaining() >= 4) {
                      unsigned int sv = UnicodeHelper::decode(in, iter);
                      if (sv == 0xFFFF) {
                          stat = APR_BADARG;
                          break;
                      }
                      int count = UnicodeHelper::encodeWide(sv, (wchar_t*) out.current());
                      out.position(out.position() + count * sizeof(wchar_t));
                  }
                  return stat;
              }

          private:
                  WideCharsetEncoder(const WideCharsetEncoder&);
                  WideCharsetEncoder& operator=(const WideCharsetEncoder&);
          };
#endif


        } // namespace helpers

}  //namespace log4cxx



CharsetEncoder::CharsetEncoder() {
}

CharsetEncoder::~CharsetEncoder() {
}

CharsetEncoderPtr CharsetEncoder::getDefaultEncoder() {
  static CharsetEncoderPtr encoder(createDefaultEncoder());
  //
  //  if invoked after static variable destruction
  //     (if logging is called in the destructor of a static object)
  //     then create a new decoder.
  // 
  if (encoder == 0) {
       return createDefaultEncoder();
  }
  return encoder;
}

CharsetEncoder* CharsetEncoder::createDefaultEncoder() {
#if LOG4CXX_LOCALE_ENCODING_UTF8
   return new UTF8CharsetEncoder();
#elif LOG4CXX_LOCALE_ENCODING_ISO_8859_1
   return new ISOLatinCharsetEncoder();
#elif LOG4CXX_LOCALE_ENCODING_US_ASCII
   return new USASCIICharsetEncoder();
#elif LOG4CXX_HAS_WCHAR_T
  return new WcstombsCharsetEncoder();
#elif APR_HAS_XLATE
  return new APRCharsetEncoder(APR_LOCALE_CHARSET);
#else
#error No default encoder available
#endif
}

#if LOG4CXX_HAS_WCHAR_T
CharsetEncoderPtr CharsetEncoder::getEncoder(const std::wstring& charset) {
   std::string cs(charset.size(), ' ');
   for(std::wstring::size_type i = 0;
      i < charset.length();
     i++) {
      cs[i] = (char) charset[i];
   }
   return getEncoder(cs);
}
#endif


#if LOG4CXX_HAS_WCHAR_T
CharsetEncoder* CharsetEncoder::createWideEncoder() {
#if LOG4CXX_LOGCHAR_IS_WCHAR
  return new TrivialCharsetEncoder();
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
  return new WideCharsetEncoder();
#endif
}


CharsetEncoderPtr CharsetEncoder::getWideEncoder() {
  static CharsetEncoderPtr encoder(createWideEncoder());
  //
  //  if invoked after static variable destruction
  //     (if logging is called in the destructor of a static object)
  //     then create a new decoder.
  // 
  if (encoder == 0) {
       return createWideEncoder();
  }
  return encoder;
}
#endif


CharsetEncoderPtr CharsetEncoder::getEncoder(const std::string& charset) {
    if (StringHelper::equalsIgnoreCase(charset, "US-ASCII", "us-ascii") ||
        StringHelper::equalsIgnoreCase(charset, "ISO646-US", "iso646-US") ||
        StringHelper::equalsIgnoreCase(charset, "ANSI_X3.4-1968", "ansi_x3.4-1968")) {
        return new USASCIICharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "ISO-8859-1", "iso-8859-1") ||
        StringHelper::equalsIgnoreCase(charset, "ISO-LATIN-1", "iso-latin-1")) {
        return new ISOLatinCharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "UTF-8", "utf-8")) {
        return new UTF8CharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "UTF-16BE", "utf-16be")
        || StringHelper::equalsIgnoreCase(charset, "UTF-16", "utf-16")) {
        return new UTF16BECharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "UTF-16LE", "utf-16le")) {
        return new UTF16LECharsetEncoder();
    }
#if defined(_WIN32)
    throw IllegalArgumentException(charset);
#else
    return new APRCharsetEncoder(charset.c_str());
#endif
}


void CharsetEncoder::reset() {
}

void CharsetEncoder::flush(ByteBuffer& /* out */ ) {
}


void CharsetEncoder::encode(CharsetEncoderPtr& enc,
    const LogString& src,
    LogString::const_iterator& iter,
    ByteBuffer& dst) {
    log4cxx_status_t stat = enc->encode(src, iter, dst);
    if (stat != APR_SUCCESS && iter != src.end()) {
#if LOG4CXX_LOGCHAR_IS_WCHAR
      iter++;
#elif LOG4CXX_LOGCHAR_IS_UTF8
      //  advance past this character and all continuation characters
     while((*(++iter) & 0xC0) == 0x80);
#else
#error logchar is unrecognized
#endif

      dst.put('?');
    }
}
