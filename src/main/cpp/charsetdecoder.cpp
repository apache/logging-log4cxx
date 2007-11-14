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
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/unicodehelper.h>
#include <log4cxx/helpers/mutex.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/helpers/pool.h>
#include <apr_xlate.h>
#include <log4cxx/private/log4cxx_private.h>
#include <locale.h>
#include <apr_portable.h>
#include <log4cxx/helpers/stringhelper.h>


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
              APRCharsetDecoder(const char* frompage) : pool(), mutex(pool) {
                if (frompage == APR_LOCALE_CHARSET) {
                    throw IllegalArgumentException("APRCharsetDecoder does not support APR_LOCALE_CHARSET.");
                }
                if (frompage == APR_DEFAULT_CHARSET) {
                    throw IllegalArgumentException("APRCharsetDecoder does not support APR_DEFAULT_CHARSET.");
                }
#if LOG4CXX_LOGCHAR_IS_WCHAR
                const char* topage = "WCHAR_T";
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
                const char* topage = "UTF-8";
#endif
                apr_status_t stat = apr_xlate_open(&convset,
                    topage,
                    frompage,
                    (apr_pool_t*) pool.getAPRPool());
                if (stat != APR_SUCCESS) {
                    throw IllegalArgumentException(frompage);
                }
              }

           /**
            *  Destructor.
            */
              virtual ~APRCharsetDecoder() {
              }

              virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  enum { BUFSIZE = 256 };
                  logchar buf[BUFSIZE];
                  const apr_size_t initial_outbytes_left = BUFSIZE * sizeof(logchar);
                  apr_status_t stat = APR_SUCCESS;
                  if (in.remaining() == 0) {
                    size_t outbytes_left = initial_outbytes_left;
                    {
                      synchronized sync(mutex);
                      stat = apr_xlate_conv_buffer((apr_xlate_t*) convset,
                        NULL, NULL, (char*) buf, &outbytes_left);
                    }
                    out.append(buf, (initial_outbytes_left - outbytes_left)/sizeof(logchar));
                  } else {
                    while(in.remaining() > 0 && stat == APR_SUCCESS) {
                      size_t inbytes_left = in.remaining();
                      size_t initial_inbytes_left = inbytes_left;
                      size_t pos = in.position();
                      apr_size_t outbytes_left = initial_outbytes_left;
                      {
                        synchronized sync(mutex);
                        stat = apr_xlate_conv_buffer((apr_xlate_t*) convset,
                           in.data() + pos,
                           &inbytes_left,
                           (char*) buf,
                           &outbytes_left);
                      }
                      out.append(buf, (initial_outbytes_left - outbytes_left)/sizeof(logchar));
                      in.position(pos + (initial_inbytes_left - inbytes_left));
                    }
                  }
                  return stat;
              }

          private:
                  APRCharsetDecoder(const APRCharsetDecoder&);
                  APRCharsetDecoder& operator=(const APRCharsetDecoder&);
                  log4cxx::helpers::Pool pool;
                  Mutex mutex;
                  apr_xlate_t *convset;
          };
          
#endif

#if LOG4CXX_LOGCHAR_IS_WCHAR && !defined(_WIN32_WCE)
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
              inline log4cxx_status_t append(LogString& out, const wchar_t* buf) {
                  out.append(buf);
                  return APR_SUCCESS;
              }

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
                      if(*src == 0) {
                           out.append(1, (logchar) 0);
                           in.position(in.position() + 1);
                      } else {
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
             int wchars = UnicodeHelper::encode(sv, buf);
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
*    Converts from US-ASCII to LogString.
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

          /**
           *    Charset decoder that uses an embedded CharsetDecoder consistent
           *     with current locale settings.
           */
          class LocaleCharsetDecoder : public CharsetDecoder {
          public:
               LocaleCharsetDecoder() : pool(), mutex(pool), decoder(), encoding() {
               }
               virtual ~LocaleCharsetDecoder() {
               }
               virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  //
                  //   assuming that all default locales are US-ASCII based (sorry no EBCDIC for now)
                  //     scan byte array for any non US-ASCII
                  const char* p = in.current();
                  size_t i = in.position();
                  for (; i < in.limit(); i++, p++) {
                      if (*((unsigned char*) p) > 127) {
                           Pool subpool;
                           const char* enc = apr_os_locale_encoding((apr_pool_t*) subpool.getAPRPool());
                           {
                                synchronized sync(mutex);
                                if (enc == 0 && decoder == 0) {
                                    encoding = "C";
                                    decoder = new USASCIICharsetDecoder();
                                } else if (encoding != enc) {
                                    encoding = enc;
                                    try {
                                       decoder = getDecoder(encoding);
                                    } catch (IllegalArgumentException& ex) {
                                       decoder = new USASCIICharsetDecoder();
                                    }
                                }
                            }
                            return decoder->decode(in, out);        
                      }
                  }
                  //
                  //    Straight US-ASCII, append bytes as characters.
                  //
#if LOG4CXX_LOGCHAR_IS_UTF8
                  out.append(in.current(), in.remaining());
#else
                  p = in.current();
                  i = in.position();
                  for (; i < in.limit(); i++, p++) {
                      out.append(1, *p);
                  }                  
#endif                               
                  in.position(in.limit()); 
                  return APR_SUCCESS;  
               }
          private:
               Pool pool;
               Mutex mutex;
               CharsetDecoderPtr decoder;
               std::string encoding;
          };

#if LOG4CXX_LOGCHAR_IS_UTF8 && LOG4CXX_HAS_WCHAR_T && (defined(_WIN32) || defined(__STDC_ISO_10646__))
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
              
#if defined(_WIN32)
			  unsigned int decodeWide(const wchar_t*& src, const wchar_t* srcEnd) {
    			unsigned int sv = *(src++);
    			if (sv < 0xDC00 || sv >= 0xDC00) {
        			return sv;
    			}
    			if (src < srcEnd) {
        			unsigned short ls = *(src++);
        			unsigned char w = (unsigned char) ((sv >> 6) & 0x0F);
        			return ((w + 1) << 16) + ((sv & 0x3F) << 10) + (ls & 0x3FF);
    			}
    			return 0xFFFF;
			  }
#endif



              virtual log4cxx_status_t decode(ByteBuffer& in,
                  LogString& out) {
                  const wchar_t* src = (const wchar_t*) (in.data() + in.position());
                  const wchar_t* srcEnd = (const wchar_t*) (in.data() + in.limit());
                  out.reserve(out.length() + in.remaining()/sizeof(wchar_t));
                  char utf8[8];
                  while(src < srcEnd) {
#if defined(__STDC_ISO_10646__)                  
                      unsigned int sv = *(src++);
#else
    				  unsigned int sv = decodeWide(src, srcEnd);
#endif    				  
                      if (sv == 0xFFFF) {
                          return APR_BADARG;
                      }
                      int bytes = UnicodeHelper::encodeUTF8(sv, utf8);
                      out.append(utf8, bytes);
                  }
                  in.position(((const char*) src) - in.data());
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
#elif LOG4CXX_LOCALE_ENCODING_ISO_8859_1 || defined(_WIN32_WCE)
     return new ISOLatinCharsetDecoder();
#elif LOG4CXX_LOCALE_ENCODING_US_ASCII
     return new USASCIICharsetDecoder();
#elif LOG4CXX_LOGCHAR_IS_WCHAR
    return new MbstowcsCharsetDecoder();
#else
    return new LocaleCharsetDecoder();
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

CharsetDecoderPtr CharsetDecoder::getUTF8Decoder() {
    static CharsetDecoderPtr decoder(new UTF8CharsetDecoder());
    //
    //  if invoked after static variable destruction
    //     (if logging is called in the destructor of a static object)
    //     then create a new decoder.
    //
    if (decoder == 0) {
       return new UTF8CharsetDecoder();
    }
    return decoder;
}

CharsetDecoderPtr CharsetDecoder::getISOLatinDecoder() {
    return new ISOLatinCharsetDecoder();
}


CharsetDecoderPtr CharsetDecoder::getDecoder(const std::string& charset) {
    if (StringHelper::equalsIgnoreCase(charset, "UTF-8", "utf-8") ||
        StringHelper::equalsIgnoreCase(charset, "UTF8", "utf8")) {
        return new UTF8CharsetDecoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "C", "c") ||
        charset == "646" ||
        StringHelper::equalsIgnoreCase(charset, "US-ASCII", "us-ascii") ||
        StringHelper::equalsIgnoreCase(charset, "ISO646-US", "iso646-US") ||
        StringHelper::equalsIgnoreCase(charset, "ANSI_X3.4-1968", "ansi_x3.4-1968")) {
        return new USASCIICharsetDecoder();
    } else if (StringHelper::equalsIgnoreCase(charset, "ISO-8859-1", "iso-8859-1") ||
        StringHelper::equalsIgnoreCase(charset, "ISO-LATIN-1", "iso-latin-1")) {
        return new ISOLatinCharsetDecoder();
    }
#if APR_HAS_XLATE || !defined(_WIN32)
    return new APRCharsetDecoder(charset.c_str());
#else    
    throw IllegalArgumentException(charset);
#endif
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

CharsetDecoderPtr CharsetDecoder::getDecoder(const std::wstring& charset) {
   std::string cs(charset.size(), ' ');
   for(std::wstring::size_type i = 0;
      i < charset.length();
     i++) {
      cs[i] = (char) charset[i];
   }
   return getDecoder(cs);
}

#endif

