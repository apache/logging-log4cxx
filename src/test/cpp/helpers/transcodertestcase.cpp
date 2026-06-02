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

#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/bytebuffer.h>
#include "../insertwide.h"
#include "../logunit.h"

#if LOG4CXX_CFSTRING_API
	#include <CoreFoundation/CFString.h>
#endif

using namespace log4cxx;
using namespace log4cxx::helpers;


LOGUNIT_CLASS(TranscoderTestCase)
{
	LOGUNIT_TEST_SUITE(TranscoderTestCase);
	LOGUNIT_TEST(decode1);
#if LOG4CXX_WCHAR_T_API
	LOGUNIT_TEST(decode2);
#endif
	LOGUNIT_TEST(decode3);
#if LOG4CXX_WCHAR_T_API
	LOGUNIT_TEST(decode4);
#endif
#if LOG4CXX_CFSTRING_API
	LOGUNIT_TEST(decode5);
#endif
	LOGUNIT_TEST(decode7);
	LOGUNIT_TEST(decode8);
#if LOG4CXX_WCHAR_T_API
	LOGUNIT_TEST(encode1);
#endif
	LOGUNIT_TEST(encode2);
#if LOG4CXX_WCHAR_T_API
	LOGUNIT_TEST(encode3);
	LOGUNIT_TEST(encode3_1);
#endif
	LOGUNIT_TEST(encode4);
#if LOG4CXX_WCHAR_T_API
	LOGUNIT_TEST(encode5);
#endif
	LOGUNIT_TEST(encode6);
#if LOG4CXX_CFSTRING_API
	LOGUNIT_TEST(encode7);
#endif
	LOGUNIT_TEST(testDecodeUTF8_1);
	LOGUNIT_TEST(testDecodeUTF8_2);
	LOGUNIT_TEST(testDecodeUTF8_3);
	LOGUNIT_TEST(testDecodeUTF8_4);
	LOGUNIT_TEST(testDecodeUTF8_RejectSurrogate);
	LOGUNIT_TEST(testDecodeUTF8_SurrogateBoundaries);
	LOGUNIT_TEST(testDecodeUTF8_U0800);
	LOGUNIT_TEST(testDecodeUTF8_RejectAboveMax);
	LOGUNIT_TEST(testDecodeUTF8_MaxBoundary);
	LOGUNIT_TEST(testDecodeUTF8_RejectInvalidLeadByte);
	LOGUNIT_TEST(testEncodeUTF16BE_BMP);
	LOGUNIT_TEST(testEncodeUTF16BE_Supplementary);
	LOGUNIT_TEST(testEncodeUTF16LE_Supplementary);
#if LOG4CXX_UNICHAR_API
	LOGUNIT_TEST(udecode2);
	LOGUNIT_TEST(udecode4);
	LOGUNIT_TEST(uencode1);
	LOGUNIT_TEST(uencode3);
	LOGUNIT_TEST(uencode5);
#endif
#if LOG4CXX_LOGCHAR_IS_UTF8
	LOGUNIT_TEST(encodeCharsetName1);
	LOGUNIT_TEST(encodeCharsetName2);
	LOGUNIT_TEST(encodeCharsetName3);
#endif
	LOGUNIT_TEST_SUITE_END();


public:
	void decode1()
	{
		const char* greeting = "Hello, World";
		LogString decoded(LOG4CXX_STR("foo\n"));
		Transcoder::decode(greeting, decoded);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\nHello, World"), decoded);
	}

#if LOG4CXX_WCHAR_T_API
	void decode2()
	{
		const wchar_t* greeting = L"Hello, World";
		LogString decoded(LOG4CXX_STR("foo\n"));
		Transcoder::decode(greeting, decoded);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\nHello, World"), decoded);
	}
#endif

	void decode3()
	{
		const char* nothing = "";
		LogString decoded(LOG4CXX_STR("foo\n"));
		Transcoder::decode(nothing, decoded);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\n"), decoded);
	}

#if LOG4CXX_WCHAR_T_API
	void decode4()
	{
		const wchar_t* nothing = L"";
		LogString decoded(LOG4CXX_STR("foo\n"));
		Transcoder::decode(nothing, decoded);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\n"), decoded);
	}
#endif

#if LOG4CXX_CFSTRING_API
	void decode5()
	{
		LogString nothing;
		LogString decoded(LOG4CXX_STR("foo\n"));
		Transcoder::decode(nothing, decoded);
		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("foo\n"), decoded);
	}
#endif


	enum { BUFSIZE = 255 };

	void decode7()
	{
		//
		//   normal characters striding over a buffer boundary
		//
		std::string longMsg(BUFSIZE - 2, 'A');
		longMsg.append("Hello");
		LogString decoded;
		Transcoder::decode(longMsg, decoded);
		LOGUNIT_ASSERT_EQUAL((size_t) BUFSIZE + 3, decoded.length());
		LOGUNIT_ASSERT_EQUAL(LogString(BUFSIZE - 2, LOG4CXX_STR('A')),
			decoded.substr(0, BUFSIZE - 2));
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Hello"),
			decoded.substr(BUFSIZE - 2 ));
	}

	void decode8()
	{
		std::string msg("Hello, World.");
		LogString actual;
		Transcoder::decode(msg, actual);
		LogString expected(LOG4CXX_STR("Hello, World."));
		LOGUNIT_ASSERT_EQUAL(expected, actual);
	}


#if LOG4CXX_WCHAR_T_API
	void encode1()
	{
		const LogString greeting(LOG4CXX_STR("Hello, World"));
		std::wstring encoded;
		Transcoder::encode(greeting, encoded);
		LOGUNIT_ASSERT_EQUAL((std::wstring) L"Hello, World", encoded);
	}
#endif

	void encode2()
	{
		const LogString greeting(LOG4CXX_STR("Hello, World"));
		std::string encoded;
		Transcoder::encode(greeting, encoded);
		LOGUNIT_ASSERT_EQUAL((std::string) "Hello, World", encoded);
	}

#if LOG4CXX_WCHAR_T_API
	void encode3()
	{
		LogString greeting(BUFSIZE - 3, LOG4CXX_STR('A'));
		greeting.append(LOG4CXX_STR("Hello"));
		std::wstring encoded;
		Transcoder::encode(greeting, encoded);
		std::wstring manyAs(BUFSIZE - 3, L'A');
		LOGUNIT_ASSERT_EQUAL(manyAs, encoded.substr(0, BUFSIZE - 3));
		LOGUNIT_ASSERT_EQUAL(std::wstring(L"Hello"), encoded.substr(BUFSIZE - 3));
	}

	void encode3_1()
	{
		// Test invalid multibyte string
		LogString greeting;
		greeting.push_back( logchar(0xff) );
		std::wstring encoded;
		Transcoder::encode(greeting, encoded);

		std::wstring expected;
		expected.push_back( log4cxx::helpers::Transcoder::LOSSCHAR );
		LOGUNIT_ASSERT_EQUAL(encoded, expected );
	}
#endif

	void encode4()
	{
		LogString greeting(BUFSIZE - 3, LOG4CXX_STR('A'));
		greeting.append(LOG4CXX_STR("Hello"));
		std::string encoded;
		Transcoder::encode(greeting, encoded);
		std::string manyAs(BUFSIZE - 3, 'A');
		LOGUNIT_ASSERT_EQUAL(manyAs, encoded.substr(0, BUFSIZE - 3));
		LOGUNIT_ASSERT_EQUAL(std::string("Hello"), encoded.substr(BUFSIZE - 3));
	}

#if LOG4CXX_WCHAR_T_API
	void encode5()
	{
		//   arbitrary, hopefully meaningless, characters from
		//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
		const wchar_t greeting[] = { L'A', 0x0605, 0x0530, 0x984, 0x40E3, 0x400, 0 };
		//
		//  decode to LogString (UTF-16 or UTF-8)
		//
		LogString decoded;
		Transcoder::decode(greeting, decoded);
		//
		//  decode to wstring
		//
		std::wstring encoded;
		Transcoder::encode(decoded, encoded);
		//
		//   should be lossless
		//
		LOGUNIT_ASSERT_EQUAL((std::wstring) greeting, encoded);
	}
#endif

	void encode6()
	{
#if LOG4CXX_LOGCHAR_IS_WCHAR || LOG4CXX_LOGCHAR_IS_UNICHAR
		//   arbitrary, hopefully meaningless, characters from
		//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
		const logchar greeting[] = { L'A', 0x0605, 0x0530, 0x984, 0x40E3, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
		const char greeting[] = { 'A',
				(char) 0xD8, (char) 0x85,
				(char) 0xD4, (char) 0xB0,
				(char) 0xE0, (char) 0xCC, (char) 0x84,
				(char) 0xE8, (char) 0x87, (char) 0x83,
				(char) 0xD0, (char) 0x80,
				0
			};
#endif

		//
		//  decode to LogString (UTF-16 or UTF-8)
		//
		LogString decoded;
		Transcoder::decode(greeting, decoded);
		//
		//  decode to wstring
		//
		std::string encoded;
		//
		//   likely 'A\u0605\u0530\u0984\u40E3\u0400'
		//
		Transcoder::encode(decoded, encoded);
	}

#if LOG4CXX_CFSTRING_API
	void encode7()
	{
		const LogString greeting(LOG4CXX_STR("Hello, World"));
		CFStringRef encoded = Transcoder::encode(greeting);
		LogString decoded;
		Transcoder::decode(encoded, decoded);
		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("Hello, World"), decoded);
	}
#endif

	void testDecodeUTF8_1()
	{
		std::string src("a");
		LogString out;
		Transcoder::decodeUTF8(src, out);
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("a")), out);
	}

	void testDecodeUTF8_2()
	{
		std::string src(1, char(0x80));
		LogString out;
		Transcoder::decodeUTF8(src, out);
		LOGUNIT_ASSERT_EQUAL(LogString(1, Transcoder::LOSSCHAR), out);
	}

	void testDecodeUTF8_3()
	{
		std::string src("\xC2");
		LogString out;
		Transcoder::decodeUTF8(src, out);
		LOGUNIT_ASSERT_EQUAL(LogString(1, Transcoder::LOSSCHAR), out);
	}

	void testDecodeUTF8_4()
	{
		std::string src("\xC2\xA9");
		LogString out;
		Transcoder::decodeUTF8(src, out);
		LogString::const_iterator iter = out.begin();
		unsigned int sv = Transcoder::decode(out, iter);
		LOGUNIT_ASSERT_EQUAL((unsigned int) 0xA9, sv);
		LOGUNIT_ASSERT_EQUAL(true, iter == out.end());
	}

	/**
	 * RFC 3629 §3 prohibits UTF-8 encodings of the UTF-16 surrogate halves
	 * (U+D800..U+DFFF). The three-byte sequences ED A0 80 .. ED BF BF must
	 * not decode to the corresponding surrogate code points: doing so lets
	 * lone surrogates enter LogString and be re-emitted by JSON/XML layouts,
	 * propagating malformed Unicode past the parsing boundary. Each byte of
	 * the invalid sequence is replaced with Transcoder::LOSSCHAR.
	 */
	void testDecodeUTF8_RejectSurrogate()
	{
		// ED A0 80 would encode U+D800 (the smallest high-surrogate).
		std::string src("\xED\xA0\x80");
		LogString out;
		Transcoder::decodeUTF8(src, out);

		LogString expected;
		expected.append(1, Transcoder::LOSSCHAR);
		expected.append(1, Transcoder::LOSSCHAR);
		expected.append(1, Transcoder::LOSSCHAR);
		LOGUNIT_ASSERT_EQUAL(expected, out);
	}

	/**
	 * U+0800 (SAMARITAN LETTER ALAF) is the smallest code point that
	 * legitimately requires a three-byte UTF-8 sequence (E0 A0 80).
	 * The overlong check in the three-byte branch of Transcoder::decode
	 * previously used `rv <= 0x800` instead of `rv < 0x800`, so this exact
	 * code point was rejected as if it were an overlong encoding and the
	 * caller substituted Transcoder::LOSSCHAR. Any UTF-8 input containing
	 * the bytes E0 A0 80 was therefore silently corrupted on decode.
	 */
	void testDecodeUTF8_U0800()
	{
		std::string src("\xE0\xA0\x80");
		LogString out;
		Transcoder::decodeUTF8(src, out);

		LogString expected;
		Transcoder::encode(0x0800, expected);
		LOGUNIT_ASSERT_EQUAL(expected, out);
		LOGUNIT_ASSERT(out.find(Transcoder::LOSSCHAR) == LogString::npos);
	}

	/**
	 * Confirm the surrogate-rejection range is exactly U+D800..U+DFFF:
	 * U+D7FF (ED 9F BF) and U+E000 (EE 80 80) bracket the range and must
	 * still decode cleanly. The four interior values are each rejected.
	 */
	void testDecodeUTF8_SurrogateBoundaries()
	{
		struct { const char* bytes; size_t len; bool reject; } cases[] =
		{
			{ "\xED\x9F\xBF", 3, false }, // U+D7FF — last valid before surrogates
			{ "\xED\xA0\x80", 3, true  }, // U+D800 — high-surrogate min (reject)
			{ "\xED\xAF\xBF", 3, true  }, // U+DBFF — high-surrogate max (reject)
			{ "\xED\xB0\x80", 3, true  }, // U+DC00 — low-surrogate min  (reject)
			{ "\xED\xBF\xBF", 3, true  }, // U+DFFF — low-surrogate max  (reject)
			{ "\xEE\x80\x80", 3, false }, // U+E000 — first valid after surrogates
		};
		for (auto& c : cases)
		{
			std::string src(c.bytes, c.len);
			LogString out;
			Transcoder::decodeUTF8(src, out);
			bool hasLoss = out.find(Transcoder::LOSSCHAR) != LogString::npos;
			LOGUNIT_ASSERT_EQUAL(c.reject, hasLoss);
		}
	}

	/**
	 * RFC 3629 §3 caps UTF-8 at U+10FFFF. Four-byte sequences with lead F5,
	 * F6, F7 (and F4 with an over-high trailer) decode to values above the
	 * Unicode maximum. Without bounds-rejection here, Transcoder::encodeUTF16
	 * later silently aliases the bogus value to a valid in-range code point
	 * (e.g. U+110000 collides with U+10000) — a substitution-collision
	 * filter-bypass primitive in wchar builds.
	 */
	void testDecodeUTF8_RejectAboveMax()
	{
		// F4 90 80 80 would encode U+110000 (one past the maximum).
		std::string src("\xF4\x90\x80\x80");
		LogString out;
		Transcoder::decodeUTF8(src, out);

		LogString expected;
		for (int i = 0; i < 4; ++i)
			expected.append(1, Transcoder::LOSSCHAR);
		LOGUNIT_ASSERT_EQUAL(expected, out);
	}

	/**
	 * Boundary check around U+10FFFF: the canonical encoding of the
	 * maximum legal code point (F4 8F BF BF) must decode cleanly; one past
	 * (F4 90 80 80) and the F5/F6/F7 lead bytes must all be rejected.
	 */
	void testDecodeUTF8_MaxBoundary()
	{
		struct { const char* bytes; size_t len; bool reject; } cases[] =
		{
			{ "\xF4\x8F\xBF\xBF", 4, false }, // U+10FFFF — maximum legal code point
			{ "\xF4\x90\x80\x80", 4, true  }, // U+110000 — one past max (reject)
			{ "\xF5\x80\x80\x80", 4, true  }, // F5 lead: rv = 0x140000 (reject)
			{ "\xF6\x80\x80\x80", 4, true  }, // F6 lead: rv = 0x180000 (reject)
			{ "\xF7\xBF\xBF\xBF", 4, true  }, // F7 lead: rv = 0x1FFFFF (reject)
		};
		for (auto& c : cases)
		{
			std::string src(c.bytes, c.len);
			LogString out;
			Transcoder::decodeUTF8(src, out);
			bool hasLoss = out.find(Transcoder::LOSSCHAR) != LogString::npos;
			LOGUNIT_ASSERT_EQUAL(c.reject, hasLoss);
		}
	}

	/**
	 * Lead bytes F8..FF never start a valid UTF-8 sequence. The four-byte
	 * branch masks the lead byte with 0x07, discarding those high bits, so
	 * F8 BF BF BF used to slip past the U+10FFFF bound and decode to U+3FFFF
	 * (and FB/FC likewise to other in-range planes) — the same aliasing
	 * filter-bypass that the F5..F7 rejection guards against. Each byte of an
	 * invalid lead sequence must be replaced with Transcoder::LOSSCHAR.
	 */
	void testDecodeUTF8_RejectInvalidLeadByte()
	{
		struct { const char* bytes; size_t len; bool reject; } cases[] =
		{
			{ "\xF0\x9F\x98\x80", 4, false }, // U+1F600 — valid four-byte
			{ "\xF8\xBF\xBF\xBF", 4, true  }, // F8 lead: masked to U+3FFFF (reject)
			{ "\xFB\xBF\xBF\xBF", 4, true  }, // FB lead: masked to U+FFFFF (reject)
			{ "\xFC\x8F\xBF\xBF", 4, true  }, // FC lead: masked to U+10FFFF (reject)
			{ "\xFF\xBF\xBF\xBF", 4, true  }, // FF lead (reject)
		};
		for (auto& c : cases)
		{
			std::string src(c.bytes, c.len);
			LogString out;
			Transcoder::decodeUTF8(src, out);
			bool hasLoss = out.find(Transcoder::LOSSCHAR) != LogString::npos;
			LOGUNIT_ASSERT_EQUAL(c.reject, hasLoss);
		}
	}

	void testEncodeUTF16BE_BMP()
	{
		char raw[4] = { 0, 0, 0, 0 };
		ByteBuffer buf(raw, sizeof(raw));
		Transcoder::encodeUTF16BE(0x4E03, buf); // CJK 七
		LOGUNIT_ASSERT_EQUAL((size_t) 2, buf.position());
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0x4E, (unsigned char) raw[0]);
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0x03, (unsigned char) raw[1]);
	}

	// U+1F600 (GRINNING FACE) encodes to UTF-16BE as D8 3D DE 00.
	// Before the fix the low surrogate's high byte was derived from bits 4-5
	// of the code point, yielding 0xDC here instead of 0xDE — corrupting the
	// pair into two unpaired surrogates.
	void testEncodeUTF16BE_Supplementary()
	{
		char raw[4] = { 0, 0, 0, 0 };
		ByteBuffer buf(raw, sizeof(raw));
		Transcoder::encodeUTF16BE(0x1F600, buf);
		LOGUNIT_ASSERT_EQUAL((size_t) 4, buf.position());
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0xD8, (unsigned char) raw[0]);
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0x3D, (unsigned char) raw[1]);
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0xDE, (unsigned char) raw[2]);
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0x00, (unsigned char) raw[3]);
	}

	void testEncodeUTF16LE_Supplementary()
	{
		char raw[4] = { 0, 0, 0, 0 };
		ByteBuffer buf(raw, sizeof(raw));
		Transcoder::encodeUTF16LE(0x1F600, buf);
		LOGUNIT_ASSERT_EQUAL((size_t) 4, buf.position());
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0x3D, (unsigned char) raw[0]);
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0xD8, (unsigned char) raw[1]);
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0x00, (unsigned char) raw[2]);
		LOGUNIT_ASSERT_EQUAL((unsigned char) 0xDE, (unsigned char) raw[3]);
	}


#if LOG4CXX_UNICHAR_API
	void udecode2()
	{
		const UniChar greeting[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', 0 };
		LogString decoded(LOG4CXX_STR("foo\n"));
		Transcoder::decode(greeting, decoded);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\nHello, World"), decoded);
	}

	void udecode4()
	{
		const UniChar nothing[] = { 0 };
		LogString decoded(LOG4CXX_STR("foo\n"));
		Transcoder::decode(nothing, decoded);
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\n"), decoded);
	}

	void uencode1()
	{
		const LogString greeting(LOG4CXX_STR("Hello, World"));
		std::basic_string<UniChar> encoded;
		Transcoder::encode(greeting, encoded);
		const UniChar expected[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', 0 };
		LOGUNIT_ASSERT_EQUAL(std::basic_string<UniChar>(expected), encoded);
	}

	void uencode3()
	{
		LogString greeting(BUFSIZE - 3, LOG4CXX_STR('A'));
		greeting.append(LOG4CXX_STR("Hello"));
		std::basic_string<UniChar> encoded;
		Transcoder::encode(greeting, encoded);
		std::basic_string<UniChar> manyAs(BUFSIZE - 3, 'A');
		LOGUNIT_ASSERT_EQUAL(manyAs, encoded.substr(0, BUFSIZE - 3));
		const UniChar hello[] = { 'H', 'e', 'l', 'l', 'o', 0 };
		LOGUNIT_ASSERT_EQUAL(std::basic_string<UniChar>(hello), encoded.substr(BUFSIZE - 3));
	}

	void uencode5()
	{
		//   arbitrary, hopefully meaningless, characters from
		//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
		const UniChar greeting[] = { L'A', 0x0605, 0x0530, 0x984, 0x40E3, 0x400, 0 };
		//
		//  decode to LogString (UTF-16 or UTF-8)
		//
		LogString decoded;
		Transcoder::decode(greeting, decoded);
		//
		//  decode to basic_string<UniChar>
		//
		std::basic_string<UniChar> encoded;
		Transcoder::encode(decoded, encoded);
		//
		//   should be lossless
		//
		LOGUNIT_ASSERT_EQUAL(std::basic_string<UniChar>(greeting), encoded);
	}
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
	void encodeCharsetName1()
	{
		const logchar utf8[] = { 0x75, 0x74, 0x66, 0x2D, 0x38, 0x00 };
		std::string encoded(Transcoder::encodeCharsetName(LogString(utf8)));
		LOGUNIT_ASSERT_EQUAL(std::string("utf-8"), encoded);
	}

	void encodeCharsetName2()
	{
		logchar lascii[0x60];
		char ascii[0x60];

		for (int i = 0; i < 0x5F; i++)
		{
			lascii[i] = i + 0x20;
			ascii[i] = i + 0x20;
		}

		lascii[0x5F] = 0;
		ascii[0x5F] = 0;
		std::string encoded(Transcoder::encodeCharsetName(LogString(ascii)));
		LOGUNIT_ASSERT_EQUAL(std::string(" !\"#$%&'()*+,-./"), encoded.substr(0, 0x10));

		if (0x40 == 'A')
		{
			LOGUNIT_ASSERT_EQUAL(std::string(ascii), encoded);
		}
	}

	void encodeCharsetName3()
	{
		logchar unsupported[] = { 0x1F, 0x7F, static_cast<logchar>(0x80), static_cast<logchar>(0x81), 0x00 };
		std::string encoded(Transcoder::encodeCharsetName(LogString(unsupported)));
		LOGUNIT_ASSERT_EQUAL(std::string("????"), encoded);
	}
#endif

};

LOGUNIT_TEST_SUITE_REGISTRATION(TranscoderTestCase);
