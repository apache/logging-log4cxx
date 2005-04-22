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
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(CharsetEncoder)

namespace log4cxx
{

        namespace helpers {

#if !defined(_WIN32)
          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
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
                    throw IllegalArgumentException(topage);
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

#if LOG4CXX_LOGCHAR_IS_WCHAR
          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
          */
          class WcstombsCharsetEncoder : public CharsetEncoder
          {
          public:
              WcstombsCharsetEncoder() {
              }
              
              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                      log4cxx_status_t stat = APR_SUCCESS;

                      if (iter != in.end()) {
                         size_t outbytes_left = out.remaining();
                         size_t initial_outbytes_left = outbytes_left;
                         size_t position = out.position();
                         LogString::size_type inOffset = (iter - in.begin());
                         size_t inchars_left = (in.size() - inOffset);
                         apr_size_t initial_inchars_left = inchars_left;
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
                                 }
                             }
                         } else {
                            iter += chunkSize;
                            out.position(out.position() + converted);
                         }
                      }
                      return stat;
              }

          private:
                  WcstombsCharsetEncoder(const WcstombsCharsetEncoder&);
                  WcstombsCharsetEncoder& operator=(const WcstombsCharsetEncoder&);
          };
#endif


#if defined(_WIN32)
          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
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
                      char* dstEnd = out.data() + out.limit();
                      char* dst = out.data() + out.position();
                      for(;
                          dst < dstEnd && iter != in.end();
                          iter++, dst++) {
                          unsigned short ch = *iter;
                          if (0x7F < ch) {
                              stat = APR_BADARG;
                              break;
                          }
                          *dst = ch;
                      }
                      out.position(dst - out.data());
                  }
                  return stat;
              }

          private:
                  USASCIICharsetEncoder(const USASCIICharsetEncoder&);
                  USASCIICharsetEncoder& operator=(const USASCIICharsetEncoder&);
          };

          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
          */
          class ISOLatin1CharsetEncoder : public CharsetEncoder
          {
          public:
              ISOLatin1CharsetEncoder() {
              }
              
#if LOG4CXX_LOGCHAR_IS_WCHAR
              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  if (iter != in.end()) {
                      char* dstEnd = out.data() + out.limit();
                      char* dst = out.data() + out.position();
                      for(;
                          dst < dstEnd && iter != in.end();
                          iter++, dst++) {
                          unsigned short ch = *iter;
                          if (0xFF < ch) {
                              stat = APR_BADARG;
                              break;
                          }
                          *dst = ch;
                      }
                      out.position(dst - out.data());
                  }
                  return stat;
              }
#endif

          private:
                  ISOLatin1CharsetEncoder(const ISOLatin1CharsetEncoder&);
                  ISOLatin1CharsetEncoder& operator=(const ISOLatin1CharsetEncoder&);
          };


          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
          */
          class UTF8CharsetEncoder : public CharsetEncoder
          {
          public:
              UTF8CharsetEncoder() {
              }

#if LOG4CXX_LOGCHAR_IS_UTF8              
              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  if (iter != in.end()) {
                      size_t inOffset = iter - in.begin();
                      char* dst = out.data() + out.position();
                      size_t count = in.length() - inOffset;
                      if (count > out.remaining()) {
                          count = out.remaining();
                      }
                      memcpy(out.data() + out.position(), 
                             in.data() + inOffset,
                             count);
                      out.position(out.position() + count);
                      iter += count;
                  }
                  return APR_SUCCESS;
              }
#endif

#if LOG4CXX_LOGCHAR_IS_WCHAR              
              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  if (iter != in.end()) {
                      size_t inOffset = iter - in.begin();
                      char* dst = out.data() + out.position();
                      char* dstEnd = out.data() + out.limit();
                      for(;
                           dst < dstEnd && iter != in.end();
                           iter++) {
                           unsigned short sv = *iter;
                           if (sv <= 0x7F) {
                               *(dst++) = sv;
                           } else if (sv <= 0x7FF) {
                               if(dst + 1 < dstEnd) {
                                   *(dst++) = 0xC0 | (sv >> 6);
                                   *(dst++) = 0x80 | (sv & 0x3F);
                               } else {
                                   break;
                               }
                           } else if (sv < 0xD800 || sv > 0xDFFF) {
                               if (dst + 2 < dstEnd) {
                                   *(dst++) = 0xE0 | (sv >> 12);
                                   *(dst++) = 0x80 | ((sv >> 6) & 0x3F);
                                   *(dst++) = 0x80 | (sv & 0x3F);
                               } else {
                                   break;
                               }
                           } else {
                               if (dst + 3 < dstEnd && (iter + 1) != in.end()) {
                                   *(dst++) = 0xF0 | ((sv >> 8) & 0x03);
                                   *(dst++) = 0x80 | ((sv >> 2) & 0x3F);
                                   unsigned short ls = *(++iter); 
                                   *(dst++) = 0x80 
                                               | ((sv & 0x03) << 4) 
                                               | ((ls >> 6) & 0x0F);
                                   *(dst++) = 0x80 | (ls & 0x3F);
                               } else {
                                   break;
                               }
                           }
                       }
                       out.position(dst - out.data());
                  }
                  return APR_SUCCESS;
              }
#endif

          private:
                  UTF8CharsetEncoder(const UTF8CharsetEncoder&);
                  UTF8CharsetEncoder& operator=(const UTF8CharsetEncoder&);
          };


          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
          */
          class UTF16BECharsetEncoder : public CharsetEncoder
          {
          public:
              UTF16BECharsetEncoder() {
              }
              
#if LOG4CXX_LOGCHAR_IS_WCHAR
              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  char* dstEnd = out.data() + out.limit() - 1;
                  char* dst = out.data() + out.position();
                  for(;
                      dst < dstEnd && iter != in.end();
                      iter++) {
                      *(dst++) = (*iter & 0xFF00) >> 8;
                      *(dst++) = *iter & 0x00FF;
                  }
                  out.position(dst - out.data());
                  return stat;
              }
#endif

          private:
                  UTF16BECharsetEncoder(const UTF16BECharsetEncoder&);
                  UTF16BECharsetEncoder& operator=(const UTF16BECharsetEncoder&);
          };

          /**
          *   An engine to transform LogStrings into bytes
          *     for the specific character set.
          */
          class UTF16LECharsetEncoder : public CharsetEncoder
          {
          public:
              UTF16LECharsetEncoder() {
              }
              
#if LOG4CXX_LOGCHAR_IS_WCHAR
              virtual log4cxx_status_t encode(const LogString& in,
                    LogString::const_iterator& iter,
                    ByteBuffer& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  char* dstEnd = out.data() + out.limit() - 1;
                  char* dst = out.data() + out.position();
                  for(;
                      dst < dstEnd && iter != in.end();
                      iter++) {
                      *(dst++) = *iter & 0x00FF;
                      *(dst++) = (*iter & 0xFF00) >> 8;
                  }
                  out.position(dst - out.data());
                  return stat;
              }
#endif

          private:
                  UTF16LECharsetEncoder(const UTF16LECharsetEncoder&);
                  UTF16LECharsetEncoder& operator=(const UTF16LECharsetEncoder&);
          };

#endif

        } // namespace helpers

}  //namespace log4cxx



CharsetEncoder::CharsetEncoder() {
}

CharsetEncoder::~CharsetEncoder() {
}

CharsetEncoderPtr CharsetEncoder::getDefaultEncoder() {
#if LOG4CXX_HAS_WCHAR_T || defined(_WIN32)
  static CharsetEncoderPtr encoder(new WcstombsCharsetEncoder());
#else
  static CharsetEncoderPtr encoder(new CharsetEncoder(APR_LOCALE_CHARSET));
#endif
  return encoder;
}


CharsetEncoderPtr CharsetEncoder::getEncoder(const std::wstring& charset) {
   std::string cs(charset.size(), ' ');
   for(int i = 0; i < charset.size(); i++) {
      cs[i] = (char) charset[i];
   }
   return getEncoder(cs);
}

CharsetEncoderPtr CharsetEncoder::getEncoder(const std::string& charset) {
#if defined(_WIN32)
    if (StringHelper::equalsIgnoreCase(charset, "US-ASCII", "us-ascii") ||
        StringHelper::equalsIgnoreCase(charset, "ISO646-US", "iso646-US")) {
        return new USASCIICharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "ISO-8859-1", "iso-8859-1") ||
        StringHelper::equalsIgnoreCase(charset, "ISO-LATIN-1", "iso-latin-1")) {
        return new ISOLatin1CharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "UTF-8", "utf-8")) {
        return new UTF8CharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "UTF-16BE", "utf-16be")
        || StringHelper::equalsIgnoreCase(charset, "UTF-16", "utf-16")) {
        return new UTF16BECharsetEncoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "UTF-16LE", "utf-16le")) {
        return new UTF16LECharsetEncoder();
    } 
    throw IllegalArgumentException(charset);
#else
   return new APRCharsetEncoder(charset.c_str());
#endif
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
