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
#define NOMINMAX /* tell windows not to define min/max macros */
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/loglog.h>
#include <apr_xlate.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>
#include <locale.h>
#include <apr_portable.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(CharsetDecoder)


namespace LOG4CXX_NS
{
namespace helpers
{

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
		APRCharsetDecoder(const LogString& frompage) : pool()
		{
#if LOG4CXX_LOGCHAR_IS_WCHAR
			const char* topage = "WCHAR_T";
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
			const char* topage = "UTF-8";
#endif
#if LOG4CXX_LOGCHAR_IS_UNICHAR
			const char* topage = "UTF-16";
#endif
			std::string fpage(Transcoder::encodeCharsetName(frompage));
			apr_status_t stat = apr_xlate_open(&convset,
					topage,
					fpage.c_str(),
					pool.getAPRPool());

			if (stat != APR_SUCCESS)
			{
				throw IllegalArgumentException(frompage);
			}
		}

		/**
		 *  Destructor.
		 */
		virtual ~APRCharsetDecoder()
		{
		}

		virtual log4cxx_status_t decode(ByteBuffer& in,
			LogString& out)
		{
			enum { BUFSIZE = 256 };
			logchar buf[BUFSIZE];
			const apr_size_t initial_outbytes_left = BUFSIZE * sizeof(logchar);
			apr_status_t stat = APR_SUCCESS;

			if (in.remaining() == 0)
			{
				size_t outbytes_left = initial_outbytes_left;
				{
					std::unique_lock<std::mutex> lock(mutex);
					stat = apr_xlate_conv_buffer((apr_xlate_t*) convset,
							NULL, NULL, (char*) buf, &outbytes_left);
				}
				out.append(buf, (initial_outbytes_left - outbytes_left) / sizeof(logchar));
			}
			else
			{
				while (in.remaining() > 0 && stat == APR_SUCCESS)
				{
					size_t inbytes_left = in.remaining();
					size_t initial_inbytes_left = inbytes_left;
					size_t pos = in.position();
					apr_size_t outbytes_left = initial_outbytes_left;
					{
						std::unique_lock<std::mutex> lock(mutex);
						stat = apr_xlate_conv_buffer((apr_xlate_t*) convset,
								in.data() + pos,
								&inbytes_left,
								(char*) buf,
								&outbytes_left);
					}
					out.append(buf, (initial_outbytes_left - outbytes_left) / sizeof(logchar));
					in.position(pos + (initial_inbytes_left - inbytes_left));
				}
			}

			return stat;
		}

	private:
		APRCharsetDecoder(const APRCharsetDecoder&);
		APRCharsetDecoder& operator=(const APRCharsetDecoder&);
		LOG4CXX_NS::helpers::Pool pool;
		std::mutex mutex;
		apr_xlate_t* convset;
};

#endif

#if LOG4CXX_LOGCHAR_IS_WCHAR && LOG4CXX_HAS_MBSRTOWCS
/**
*    Converts from the default multi-byte string to
*        LogString using mbstowcs.
*
*/
class MbstowcsCharsetDecoder : public CharsetDecoder
{
	public:
		MbstowcsCharsetDecoder()
		{
		}

		virtual ~MbstowcsCharsetDecoder()
		{
		}

	private:
		inline log4cxx_status_t append(LogString& out, const wchar_t* buf)
		{
			out.append(buf);
			return APR_SUCCESS;
		}

		virtual log4cxx_status_t decode(ByteBuffer& in,
			LogString& out)
		{
			log4cxx_status_t stat = APR_SUCCESS;
			enum { BUFSIZE = 256 };
			wchar_t wbuf[BUFSIZE];
			char cbuf[BUFSIZE*4];

			mbstate_t mbstate;
			memset(&mbstate, 0, sizeof(mbstate));

			while (in.remaining() > 0)
			{
				const char* src = in.current();

				if (*src == 0)
				{
					out.append(1, (logchar) 0);
					in.position(in.position() + 1);
				}
				else
				{
					auto available = std::min(sizeof (cbuf) - 1, in.remaining());
					strncpy(cbuf, src, available);
					cbuf[available] = 0;
					src = cbuf;
					size_t wCharCount = mbsrtowcs(wbuf,
							&src,
							BUFSIZE - 1,
							&mbstate);
					auto converted = src - cbuf;
					in.position(in.position() + converted);

					if (wCharCount == (size_t) -1) // Illegal byte sequence?
					{
						LogString msg(LOG4CXX_STR("Illegal byte sequence at "));
						msg.append(std::to_wstring(in.position()));
						msg.append(LOG4CXX_STR(" of "));
						msg.append(std::to_wstring(in.limit()));
						LogLog::warn(msg);
						stat = APR_BADCH;
						break;
					}
					else
					{
						wbuf[wCharCount] = 0;
						stat = append(out, wbuf);
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
		TrivialCharsetDecoder()
		{
		}

		virtual ~TrivialCharsetDecoder()
		{
		}

		virtual log4cxx_status_t decode(ByteBuffer& in,
			LogString& out)
		{
			size_t remaining = in.remaining();

			if ( remaining > 0)
			{
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
#else
/**
*    Converts from UTF-8 to std::wstring
*
*/
class UTF8CharsetDecoder : public CharsetDecoder
{
	public:
		UTF8CharsetDecoder()
		{
		}

		virtual ~UTF8CharsetDecoder()
		{
		}

	private:
		virtual log4cxx_status_t decode(ByteBuffer& in,
			LogString& out)
		{
			if (in.remaining() > 0)
			{
				std::string tmp(in.current(), in.remaining());
				std::string::const_iterator iter = tmp.begin();

				while (iter != tmp.end())
				{
					unsigned int sv = Transcoder::decode(tmp, iter);

					if (sv == 0xFFFF)
					{
						size_t offset = iter - tmp.begin();
						in.position(in.position() + offset);
						return APR_BADARG;
					}
					else
					{
						Transcoder::encode(sv, out);
					}
				}

				in.position(in.limit());
			}

			return APR_SUCCESS;
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
		ISOLatinCharsetDecoder()
		{
		}

		virtual ~ISOLatinCharsetDecoder()
		{
		}

	private:
		virtual log4cxx_status_t decode(ByteBuffer& in,
			LogString& out)
		{
			if (in.remaining() > 0)
			{

				const unsigned char* src = (unsigned char*) in.current();
				const unsigned char* srcEnd = src + in.remaining();

				while (src < srcEnd)
				{
					unsigned int sv = *(src++);
					Transcoder::encode(sv, out);
				}

				in.position(in.limit());
			}

			return APR_SUCCESS;
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
		USASCIICharsetDecoder()
		{
		}

		virtual ~USASCIICharsetDecoder()
		{
		}

	private:

		virtual log4cxx_status_t decode(ByteBuffer& in,
			LogString& out)
		{
			log4cxx_status_t stat = APR_SUCCESS;

			if (in.remaining() > 0)
			{

				const unsigned char* src = (unsigned char*) in.current();
				const unsigned char* srcEnd = src + in.remaining();

				while (src < srcEnd)
				{
					unsigned char sv = *src;

					if (sv < 0x80)
					{
						src++;
						Transcoder::encode(sv, out);
					}
					else
					{
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
 *    Charset decoder that uses current locale settings.
 */
class LocaleCharsetDecoder : public CharsetDecoder
{
	public:
		LocaleCharsetDecoder() : state()
		{
		}
		log4cxx_status_t decode(ByteBuffer& in, LogString& out) override
		{
			log4cxx_status_t result = APR_SUCCESS;
			const char* p = in.current();
			size_t i = in.position();
			size_t remain = in.limit() - i;
#if !LOG4CXX_CHARSET_EBCDIC
			if (std::mbsinit(&this->state)) // ByteBuffer not partially decoded?
			{
				// Copy single byte characters
				for (; 0 < remain && ((unsigned int) *p) < 0x80; --remain, ++i, p++)
				{
					out.append(1, *p);
				}
			}
#endif
			// Decode characters that may be represented by multiple bytes
			while (0 < remain)
			{
				wchar_t ch = 0;
				size_t n = std::mbrtowc(&ch, p, remain, &this->state);
				if (0 == n) // NULL encountered?
				{
					++i;
					break;
				}
				if (static_cast<std::size_t>(-1) == n) // decoding error?
				{
					result = APR_BADARG;
					break;
				}
				if (static_cast<std::size_t>(-2) == n) // incomplete sequence?
				{
					break;
				}
				Transcoder::encode(static_cast<unsigned int>(ch), out);
				remain -= n;
				i += n;
				p += n;
			}
			in.position(i);
			return result;
		}

	private:
		std::mbstate_t state;
};



} // namespace helpers

}  //namespace log4cxx


CharsetDecoder::CharsetDecoder()
{
}


CharsetDecoder::~CharsetDecoder()
{
}

CharsetDecoder* CharsetDecoder::createDefaultDecoder()
{
#if LOG4CXX_CHARSET_UTF8
	return new UTF8CharsetDecoder();
#elif LOG4CXX_CHARSET_ISO88591 || defined(_WIN32_WCE)
	return new ISOLatinCharsetDecoder();
#elif LOG4CXX_CHARSET_USASCII
	return new USASCIICharsetDecoder();
#elif LOG4CXX_LOGCHAR_IS_WCHAR && LOG4CXX_HAS_MBSRTOWCS
	return new MbstowcsCharsetDecoder();
#else
	return new LocaleCharsetDecoder();
#endif
}

CharsetDecoderPtr CharsetDecoder::getDefaultDecoder()
{
	static WideLife<CharsetDecoderPtr> decoder(createDefaultDecoder());

	//
	//  if invoked after static variable destruction
	//     (if logging is called in the destructor of a static object)
	//     then create a new decoder.
	//
	if (decoder.value() == 0)
	{
		return CharsetDecoderPtr( createDefaultDecoder() );
	}

	return decoder;
}

CharsetDecoderPtr CharsetDecoder::getUTF8Decoder()
{
	static WideLife<CharsetDecoderPtr> decoder(new UTF8CharsetDecoder());

	//
	//  if invoked after static variable destruction
	//     (if logging is called in the destructor of a static object)
	//     then create a new decoder.
	//
	if (decoder.value() == 0)
	{
		return std::make_shared<UTF8CharsetDecoder>();
	}

	return decoder;
}

CharsetDecoderPtr CharsetDecoder::getISOLatinDecoder()
{
	return std::make_shared<ISOLatinCharsetDecoder>();
}


CharsetDecoderPtr CharsetDecoder::getDecoder(const LogString& charset)
{
	if (StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("UTF-8"), LOG4CXX_STR("utf-8")) ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("UTF8"), LOG4CXX_STR("utf8")) ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("CP65001"), LOG4CXX_STR("cp65001")))
	{
		return std::make_shared<UTF8CharsetDecoder>();
	}
	else if (StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("C"), LOG4CXX_STR("c")) ||
		charset == LOG4CXX_STR("646") ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("US-ASCII"), LOG4CXX_STR("us-ascii")) ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("ISO646-US"), LOG4CXX_STR("iso646-US")) ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("ANSI_X3.4-1968"), LOG4CXX_STR("ansi_x3.4-1968")) ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("CP20127"), LOG4CXX_STR("cp20127")))
	{
		return std::make_shared<USASCIICharsetDecoder>();
	}
	else if (StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("ISO-8859-1"), LOG4CXX_STR("iso-8859-1")) ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("ISO-LATIN-1"), LOG4CXX_STR("iso-latin-1")) ||
		StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("CP1252"), LOG4CXX_STR("cp1252")))
	{
		return std::make_shared<ISOLatinCharsetDecoder>();
	}
	else if (StringHelper::equalsIgnoreCase(charset, LOG4CXX_STR("LOCALE"), LOG4CXX_STR("locale")))
	{
		return std::make_shared<LocaleCharsetDecoder>();
	}

#if APR_HAS_XLATE
	return std::make_shared<APRCharsetDecoder>(charset);
#else
	throw IllegalArgumentException(charset);
#endif
}






