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

#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/unicodehelper.h>
#include <apr_xlate.h>


using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(CharsetDecoder)


namespace log4cxx
{
        namespace helpers {

#if APR_HAS_XLATE
          /**
           *  Converts from an arbitrary encoding to LogString
           *    using apr_xlate.  Requires real iconv implementation,
         *    apr-iconv will crash in use.
           */
          class APRCharsetDecoder : public CharsetDecoder
          {
          public:
           /**
            *  Creates a new instance.
            *  @param frompage name of source encoding.
            */
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

           /**
            *  Destructor.
            */
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

#if LOG4CXX_HAS_WCHAR_T
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

          private:
#if LOG4CXX_LOGCHAR_IS_WCHAR
              inline log4cxx_status_t append(LogString& out, const wchar_t* buf) {
                  out.append(buf);
                  return APR_SUCCESS;
              }
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
              log4cxx_status_t append(LogString& out, const wchar_t* buf) {
                  char utf8[8];
                  const wchar_t* current = buf;
                  const wchar_t* end = wcschr(buf, 0);
                  while(current < end) {
                      unsigned int sv = UnicodeHelper::decodeWide(current, end);
                      if (sv == 0xFFFF) {
                          return APR_BADARG;
                      }
                      int bytes = UnicodeHelper::encodeUTF8(sv, utf8);
                      out.append(utf8, bytes);
                  }
                  return APR_SUCCESS;
              }
#endif

              virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  log4cxx_status_t stat = APR_SUCCESS;
                  enum { BUFSIZE = 256 };
                  wchar_t buf[BUFSIZE];

                  mbstate_t mbstate;
                  memset(&mbstate, 0, sizeof(mbstate));

                  while(in.remaining() > 0) {
                      size_t requested = in.remaining();
                      if (requested > BUFSIZE - 1) {
                          requested = BUFSIZE - 1;
                      }

                      memset(buf, 0, BUFSIZE*sizeof(wchar_t));
                      const char* src = in.current();
                      size_t converted = mbsrtowcs(buf,
                           &src,
                           requested,
                           &mbstate);
                      if (converted == (size_t) -1) {
                          stat = APR_BADARG;
                          in.position(src - in.data());
                          break;
                      } else {
                         stat = append(out, buf);
                         in.position(in.position() + converted);
                      }
                  }
                  return stat;
              }



          private:
                  MbstowcsCharsetDecoder(const MbstowcsCharsetDecoder&);
                  MbstowcsCharsetDecoder& operator=(const MbstowcsCharsetDecoder&);
          };
#endif


          /**
          *    Decoder used when the external and internal charsets
          *    are the same.
          *
          */
          class TrivialCharsetDecoder : public CharsetDecoder
          {
          public:
              TrivialCharsetDecoder() {
              }

              virtual ~TrivialCharsetDecoder() {
              }

              virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  size_t remaining = in.remaining();
              if( remaining > 0) {
               const logchar* src = (const logchar*) (in.data() + in.position());
               size_t count = remaining / sizeof(logchar);
               out.append(src, count);
               in.position(in.position() + remaining);
              }
                  return APR_SUCCESS;
              }



          private:
                  TrivialCharsetDecoder(const TrivialCharsetDecoder&);
                  TrivialCharsetDecoder& operator=(const TrivialCharsetDecoder&);
          };


#if LOG4CXX_LOGCHAR_IS_UTF8
typedef TrivialCharsetDecoder UTF8CharsetDecoder;
#endif

#if LOG4CXX_LOGCHAR_IS_WCHAR
/**
*    Converts from UTF-8 to std::wstring
*
*/
class UTF8CharsetDecoder : public CharsetDecoder
{
public:
    UTF8CharsetDecoder() {
    }

    virtual ~UTF8CharsetDecoder() {
    }

private:
    virtual log4cxx_status_t decode(ByteBuffer& in,
        LogString& out) {
        log4cxx_status_t stat = APR_SUCCESS;
        if (in.remaining() > 0) {
          wchar_t buf[2];

          const char* src = in.current();
          const char* srcEnd = in.data() + in.limit();
          while(src < srcEnd) {
             unsigned int sv = UnicodeHelper::decodeUTF8(src, srcEnd);
             if (sv == 0xFFFF) {
                stat = APR_BADARG;
                break;
             }
             int wchars = UnicodeHelper::encodeWide(sv, buf);
             out.append(buf, wchars);
          }
          in.position(src - in.data());
        }
        return stat;
    }



private:
        UTF8CharsetDecoder(const UTF8CharsetDecoder&);
        UTF8CharsetDecoder& operator=(const UTF8CharsetDecoder&);
};
#endif

/**
*    Converts from ISO-8859-1 to LogString.
*
*/
class ISOLatinCharsetDecoder : public CharsetDecoder
{
public:
    ISOLatinCharsetDecoder() {
    }

    virtual ~ISOLatinCharsetDecoder() {
    }

private:
    virtual log4cxx_status_t decode(ByteBuffer& in,
        LogString& out) {
        log4cxx_status_t stat = APR_SUCCESS;
        if (in.remaining() > 0) {
          logchar buf[8];

          const unsigned char* src = (unsigned char*) in.current();
          const unsigned char* srcEnd = src + in.remaining();
          while(src < srcEnd) {
             unsigned int sv = *(src++);
             int logchars = UnicodeHelper::encode(sv, buf);
             out.append(buf, logchars);
          }
          in.position(in.limit());
        }
        return stat;
    }



private:
        ISOLatinCharsetDecoder(const ISOLatinCharsetDecoder&);
        ISOLatinCharsetDecoder& operator=(const ISOLatinCharsetDecoder&);
};


/**
*    Converts from ISO-8859-1 to LogString.
*
*/
class USASCIICharsetDecoder : public CharsetDecoder
{
public:
    USASCIICharsetDecoder() {
    }

    virtual ~USASCIICharsetDecoder() {
    }

private:

  virtual log4cxx_status_t decode(ByteBuffer& in,
      LogString& out) {
      log4cxx_status_t stat = APR_SUCCESS;
      if (in.remaining() > 0) {
        logchar buf[8];

        const unsigned char* src = (unsigned char*) in.current();
        const unsigned char* srcEnd = src + in.remaining();
        while(src < srcEnd) {
           unsigned char sv = *src;
           if (sv < 0x80) {
              src++;
              int logchars = UnicodeHelper::encode(sv, buf);
              out.append(buf, logchars);
           } else {
             stat = APR_BADARG;
             break;
           }
        }
        in.position(src - (const unsigned char*) in.data());
      }
      return stat;
    }



private:
        USASCIICharsetDecoder(const USASCIICharsetDecoder&);
        USASCIICharsetDecoder& operator=(const USASCIICharsetDecoder&);
};


#if LOG4CXX_LOGCHAR_IS_UTF8 && LOG4CXX_HAS_WCHAR_T
          /**
          *    Decoder to convert array of wchar_t to UTF-8 bytes.
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
                  const wchar_t* src = (const wchar_t*) (in.data() + in.position());
                  const wchar_t* srcEnd = (const wchar_t*) (in.data() + in.limit());
                  out.reserve(out.length() + in.remaining()/sizeof(wchar_t));
                  char utf8[8];
                  while(src < srcEnd) {
                      unsigned int sv = UnicodeHelper::decodeWide(src, srcEnd);
                      if (sv == 0xFFFF) {
                          return APR_BADARG;
                      }
                      int bytes = UnicodeHelper::encodeUTF8(sv, utf8);
                      out.append(utf8, bytes);
                  }
                  in.position(((char*) src) - in.data());
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

CharsetDecoder* CharsetDecoder::createDefaultDecoder() {
#if LOG4CXX_LOCALE_ENCODING_UTF8
     return new UTF8CharsetDecoder();
#elif LOG4CXX_LOCALE_ENCODING_ISO_8859_1
     return new ISOLatinCharsetDecoder();
#elif LOG4CXX_LOCALE_ENCODING_US_ASCII
     return new USASCIICharsetDecoder();
#elif LOG4CXX_HAS_WCHAR_T
    return new MbstowcsCharsetDecoder();
#elif APR_HAS_XLATE
    return new APRCharsetDecoder(APR_LOCALE_CHARSET);
#else
#error No default charset decoder available
#endif
}

CharsetDecoderPtr CharsetDecoder::getDefaultDecoder() {
    static CharsetDecoderPtr decoder(createDefaultDecoder());
    //
    //  if invoked after static variable destruction
    //     (if logging is called in the destructor of a static object)
    //     then create a new decoder.
    // 
    if (decoder == 0) {
       return createDefaultDecoder();
    }
    return decoder;
}

#if LOG4CXX_HAS_WCHAR_T
CharsetDecoder* CharsetDecoder::createWideDecoder() {
#if LOG4CXX_LOGCHAR_IS_WCHAR
  return new TrivialCharsetDecoder();
#elif defined(_WIN32) || defined(__STDC_ISO_10646__)
  return new WideToUTF8CharsetDecoder();
#else
  return new APRCharsetDecoder("WCHAR_T");
#endif
}

  
CharsetDecoderPtr CharsetDecoder::getWideDecoder() {
  static CharsetDecoderPtr decoder(createWideDecoder());
    //
    //  if invoked after static variable destruction
    //     (if logging is called in the destructor of a static object)
    //     then create a new decoder.
    // 
  if (decoder == 0) {
     return createWideDecoder();
  }
  return decoder;
}
#endif

