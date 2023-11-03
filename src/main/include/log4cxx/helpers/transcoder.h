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

#ifndef _LOG4CXX_HELPERS_TRANSCODER_H
#define _LOG4CXX_HELPERS_TRANSCODER_H

#include <log4cxx/logstring.h>


namespace LOG4CXX_NS
{
namespace helpers
{
class ByteBuffer;
class Pool;
/**
*    Simple transcoder for converting between
*      external char and wchar_t strings and
*      internal strings.
*
*/
class LOG4CXX_EXPORT Transcoder
{
	public:


		/**
		 *   Appends this specified string of UTF-8 characters to LogString.
		 */
		static void decodeUTF8(const std::string& src, LogString& dst);
		/**
		 *    Converts the LogString to a UTF-8 string.
		 */
		static void encodeUTF8(const LogString& src, std::string& dst);
		/**
		 *    Converts the LogString to a UTF-8 string.
		 */
		static char* encodeUTF8(const LogString& src, LOG4CXX_NS::helpers::Pool& p);
		/**
		 *    Append UCS-4 code point to a byte buffer as UTF-8.
		 */
		static void encodeUTF8(unsigned int sv, ByteBuffer& dst);
		/**
		 *    Append UCS-4 code point to a byte buffer as UTF-16LE.
		 */
		static void encodeUTF16LE(unsigned int sv, ByteBuffer& dst);
		/**
		 *    Append UCS-4 code point to a byte buffer as UTF-16BE.
		 */
		static void encodeUTF16BE(unsigned int sv, ByteBuffer& dst);


		/**
		 *   Decodes next character from a UTF-8 string.
		 *   @param in string from which the character is extracted.
		 *   @param iter iterator addressing start of character, will be
		 *   advanced to next character if successful.
		 *   @return scalar value (UCS-4) or 0xFFFF if invalid sequence.
		 */
		static unsigned int decode(const std::string& in,
			std::string::const_iterator& iter);

		/**
		  *   Appends UCS-4 value to a UTF-8 string.
		  *   @param ch UCS-4 value.
		  *   @param dst destination.
		  */
		static void encode(unsigned int ch, std::string& dst);

		/**
		 *    Appends string in the current code-page
		 *       to a LogString.
		 */
		static void decode(const std::string& src, LogString& dst);

		/**
		 *     Appends a LogString to a string in the current
		 *        code-page.  Unrepresentable characters may be
		 *        replaced with loss characters.
		*/
		static void encode(const LogString& src, std::string& dst);

		/**
		  *     Encodes the specified LogString to the current
		  *       character set.
		  *      @param src string to encode.
		  *      @param p pool from which to allocate return value.
		  *      @return pool allocated string.
		  */
		static char* encode(const LogString& src, LOG4CXX_NS::helpers::Pool& p);



#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR_T || defined(WIN32) || defined(_WIN32)
		static void decode(const std::wstring& src, LogString& dst);
		static void encode(const LogString& src, std::wstring& dst);
		static wchar_t* wencode(const LogString& src, LOG4CXX_NS::helpers::Pool& p);

		/**
		 *   Decodes next character from a wstring.
		 *   @param in string from which the character is extracted.
		 *   @param iter iterator addressing start of character, will be
		 *   advanced to next character if successful.
		 *   @return scalar value (UCS-4) or 0xFFFF if invalid sequence.
		 */
		static unsigned int decode(const std::wstring& in,
			std::wstring::const_iterator& iter);

		/**
		  *   Appends UCS-4 value to a UTF-8 string.
		  *   @param ch UCS-4 value.
		  *   @param dst destination.
		  */
		static void encode(unsigned int ch, std::wstring& dst);

#endif


#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
		static void decode(const std::basic_string<UniChar>& src, LogString& dst);
		static void encode(const LogString& src, std::basic_string<UniChar>& dst);

		/**
		 *   Decodes next character from a UniChar string.
		 *   @param in string from which the character is extracted.
		 *   @param iter iterator addressing start of character, will be
		 *   advanced to next character if successful.
		 *   @return scalar value (UCS-4) or 0xFFFF if invalid sequence.
		 */
		static unsigned int decode(const std::basic_string<UniChar>& in,
			std::basic_string<UniChar>::const_iterator& iter);

		/**
		  *   Appends UCS-4 value to a UTF-8 string.
		  *   @param ch UCS-4 value.
		  *   @param dst destination.
		  */
		static void encode(unsigned int ch, std::basic_string<UniChar>& dst);

#endif

#if LOG4CXX_CFSTRING_API
		static void decode(const CFStringRef& src, LogString& dst);
		static CFStringRef encode(const LogString& src);
#endif

		enum { LOSSCHAR = 0x3F };

		/**
		 *   Returns a logchar value given a character literal in the ASCII charset.
		 *   Used to implement the LOG4CXX_STR macro for EBCDIC and UNICHAR.
		 */
		static logchar decode(char v);
		/**
		 *   Returns a LogString given a string literal in the ASCII charset.
		 *   Used to implement the LOG4CXX_STR macro for EBCDIC and UNICHAR.
		 */
		static LogString decode(const char* v);

		/**
		 *   Encodes a charset name in the default encoding
		 *      without using a CharsetEncoder (which could trigger recursion).
		 */
		static std::string encodeCharsetName(const LogString& charsetName);

	private:

	private:
		Transcoder();
		Transcoder(const Transcoder&);
		Transcoder& operator=(const Transcoder&);
		enum { BUFSIZE = 256 };
		static size_t encodeUTF8(unsigned int ch, char* dst);
		static size_t encodeUTF16BE(unsigned int ch, char* dst);
		static size_t encodeUTF16LE(unsigned int ch, char* dst);

};
}
}

#if LOG4CXX_CHARSET_UTF8 && LOG4CXX_LOGCHAR_IS_UTF8
/** Create a std::string equivalent of \c src.

	Defines a std::string variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new std::string variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_CHAR(var, src) \
	const std::string& var = src

/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the std::string \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The std::string variable.
*/
#define LOG4CXX_DECODE_CHAR(var, src) \
	const LOG4CXX_NS::LogString& var = src

#else
/** Create a std::string equivalent of \c src.

	Defines a std::string variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new std::string variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_CHAR(var, src) \
	std::string var;                      \
	LOG4CXX_NS::helpers::Transcoder::encode(src, var)

/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the std::string \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The std::string variable.
*/
#define LOG4CXX_DECODE_CHAR(var, src) \
	LOG4CXX_NS::LogString var;                      \
	LOG4CXX_NS::helpers::Transcoder::decode(src, var)
#endif

/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the CFStringRef \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The CFStringRef variable.
*/
#define LOG4CXX_DECODE_CFSTRING(var, src) \
	LOG4CXX_NS::LogString var;                      \
	LOG4CXX_NS::helpers::Transcoder::decode(src, var)

/** Create a CFStringRef equivalent of \c src.

	Defines a CFStringRef variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new CFStringRef variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_CFSTRING(var, src) \
	CFStringRef var = LOG4CXX_NS::helpers::Transcoder::encode(src)

#if LOG4CXX_LOGCHAR_IS_WCHAR
/** Create a std::wstring equivalent of \c src.

	Defines a std::wstring variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new std::wstring variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_WCHAR(var, src) \
	const std::wstring& var = src

/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the std::wstring \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The std::wstring variable.
*/
#define LOG4CXX_DECODE_WCHAR(var, src) \
	const LOG4CXX_NS::LogString& var = src

#else
/** Create a std::wstring equivalent of \c src.

	Defines a std::wstring variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new std::wstring variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_WCHAR(var, src) \
	std::wstring var;                      \
	LOG4CXX_NS::helpers::Transcoder::encode(src, var)

/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the std::wstring \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The std::wstring variable.
*/
#define LOG4CXX_DECODE_WCHAR(var, src) \
	LOG4CXX_NS::LogString var;                      \
	LOG4CXX_NS::helpers::Transcoder::decode(src, var)

#endif

#if LOG4CXX_LOGCHAR_IS_UNICHAR

/** Create a std::basic_string<UniChar> equivalent of \c src.

	Defines a std::basic_string<UniChar> variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new std::basic_string<UniChar> variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_UNICHAR(var, src) \
	const std::basic_string<UniChar>& var = src

/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the std::basic_string<UniChar> \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The std::basic_string<UniChar> variable.
*/
#define LOG4CXX_DECODE_UNICHAR(var, src) \
	const LOG4CXX_NS::LogString& var = src

#else

/** Create a std::basic_string<UniChar> equivalent of \c src.

	Defines a std::basic_string<UniChar> variable \c var
	initialized with characters
	equivalent to the log4cxx::LogString \c src contents.

	@param var The name of the new std::basic_string<UniChar> variable.
	@param src The log4cxx::LogString variable.
*/
#define LOG4CXX_ENCODE_UNICHAR(var, src) \
	std::basic_string<UniChar> var;          \
	LOG4CXX_NS::helpers::Transcoder::encode(src, var)

/** Create a log4cxx::LogString equivalent of \c src.

	Defines a log4cxx::LogString variable \c var
	initialized with characters
	equivalent to the std::basic_string<UniChar> \c src contents.

	@param var The name of the new log4cxx::LogString variable.
	@param src The std::basic_string<UniChar> variable.
*/
#define LOG4CXX_DECODE_UNICHAR(var, src) \
	LOG4CXX_NS::LogString var;                      \
	LOG4CXX_NS::helpers::Transcoder::decode(src, var)

#endif

#endif //_LOG4CXX_HELPERS_TRANSCODER_H
