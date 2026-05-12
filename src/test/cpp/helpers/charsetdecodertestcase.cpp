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

#include <log4cxx/private/string_c11.h>
#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/transcoder.h>
#include "../logunit.h"
#include "../insertwide.h"
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/loglog.h>
#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


#define APR_SUCCESS ((log4cxx_status_t) 0)



LOGUNIT_CLASS(CharsetDecoderTestCase)
{
	LOGUNIT_TEST_SUITE(CharsetDecoderTestCase);
	LOGUNIT_TEST(decode1);
	LOGUNIT_TEST(decode2);
	LOGUNIT_TEST(decode3);
	LOGUNIT_TEST(decode4);
	LOGUNIT_TEST(testISOLatinHighBytes);
#if LOG4CXX_LOGCHAR_IS_WCHAR && LOG4CXX_HAS_MBSRTOWCS
    LOGUNIT_TEST(testMbstowcsInfiniteLoop);
#endif
	LOGUNIT_TEST_SUITE_END();

	enum { BUFSIZE = 256 };

public:


	void decode1()
	{
		char buf[] = "Hello, World";
		ByteBuffer src(buf, strlen(buf));

		CharsetDecoderPtr dec(CharsetDecoder::getDefaultDecoder());
		LogString greeting;
		log4cxx_status_t stat = dec->decode(src, greeting);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

		stat = dec->decode(src, greeting);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		LOGUNIT_ASSERT_EQUAL((size_t) 12, src.position());

		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Hello, World"), greeting);
	}

	void decode2()
	{
		char buf[BUFSIZE + 6];
		memset(buf, 'A', BUFSIZE);
		buf[BUFSIZE - 3] = 0;
		strcat_s(buf, sizeof buf, "Hello");
		ByteBuffer src(buf, strlen(buf));

		CharsetDecoderPtr dec(CharsetDecoder::getDefaultDecoder());

		LogString greeting;
		log4cxx_status_t stat = dec->decode(src, greeting);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		LOGUNIT_ASSERT_EQUAL((size_t) 0, src.remaining());


		stat = dec->decode(src, greeting);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

		LogString manyAs(BUFSIZE - 3, LOG4CXX_STR('A'));
		LOGUNIT_ASSERT_EQUAL(manyAs, greeting.substr(0, BUFSIZE - 3));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Hello")), greeting.substr(BUFSIZE - 3));
	}

	void decode3()
	{
		char buf[] = { 'H', 'e', 'l', 'l', 'o', ',', 0, 'W', 'o', 'r', 'l', 'd'};
		ByteBuffer src(buf, 12);

		CharsetDecoderPtr dec(CharsetDecoder::getDefaultDecoder());
		LogString greeting;
		log4cxx_status_t stat = dec->decode(src, greeting);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

		stat = dec->decode(src, greeting);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		LOGUNIT_ASSERT_EQUAL((size_t) 12, src.position());

		const logchar expected[] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x00, 0x57, 0x6F, 0x72, 0x6C, 0x64 };
		LOGUNIT_ASSERT_EQUAL(LogString(expected, 12), greeting);
	}

	void decode4()
	{
		char utf8_greet[] = { 'A',
				(char) 0xD8, (char) 0x85,
				(char) 0xD4, (char) 0xB0,
				(char) 0xE0, (char) 0xA6, (char) 0x86,
				(char) 0xE4, (char) 0xB8, (char) 0x83,
				(char) 0xD0, (char) 0x80,
				0
			};
#if LOG4CXX_LOGCHAR_IS_WCHAR || LOG4CXX_LOGCHAR_IS_UNICHAR
		//   arbitrary, hopefully meaningless, characters from
		//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
		const logchar greet[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
		const logchar* greet = utf8_greet;
#endif

		try
		{
			std::locale::global(std::locale("en_US.UTF-8"));
			auto dec = CharsetDecoder::getDecoder(LOG4CXX_STR("locale"));

			ByteBuffer in(utf8_greet, sizeof (utf8_greet));
			LogString out;
			log4cxx_status_t stat = dec->decode(in, out);
			LOGUNIT_ASSERT_EQUAL(false, CharsetDecoder::isError(stat));
			stat = dec->decode(in, out);
			LOGUNIT_ASSERT_EQUAL(false, CharsetDecoder::isError(stat));
			LOGUNIT_ASSERT(out == greet);
		}
		catch (std::runtime_error& ex)
		{
			LogString msg;
			Transcoder::decode(ex.what(), msg);
			msg.append(LOG4CXX_STR(": "));
			msg.append(LOG4CXX_STR("en_US.UTF-8"));
			LogLog::warn(msg);
		}
	}

	/**
	 * Decoding ISO-8859-1 must map every byte 0x80..0xFF to the
	 * code point of the same numeric value. On platforms where plain
	 * char is signed (default on MSVC/GCC/Clang for x86/x64), a
	 * static_cast<unsigned int>(*src) sign-extends bytes >= 0x80 into
	 * 0xFFFFFFxx, which Transcoder::encode then treats as out-of-range
	 * Unicode and replaces with U+FFFD (or appends garbage on wchar_t
	 * builds). The .properties configuration loader uses this decoder
	 * per the Java spec, so the bug silently corrupts any non-ASCII
	 * Latin-1 byte that appears in a log4cxx configuration file.
	 */
	void testISOLatinHighBytes()
	{
		char buf[1];
		auto dec = CharsetDecoder::getISOLatinDecoder();
		for (unsigned int b = 0x80; b <= 0xFF; ++b)
		{
			buf[0] = static_cast<char>(b);
			ByteBuffer in(buf, 1);
			LogString out;
			log4cxx_status_t stat = dec->decode(in, out);
			LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

			// Build the expected LogString by encoding code point b
			// through the same Transcoder path the decoder uses.
			LogString expected;
			Transcoder::encode(b, expected);
			LOGUNIT_ASSERT_EQUAL(expected, out);
		}
	}

#if LOG4CXX_LOGCHAR_IS_WCHAR && LOG4CXX_HAS_MBSRTOWCS
    /**
     * Tests that we don't loop infinitely when mbsrtowcs refuses to consume
     * an incomplete multibyte sequence at the end of the buffer.
     */
    void testMbstowcsInfiniteLoop()
    {
        // 1. setup: buffer ending with a partial multibyte sequence.
        // 0xC2 is a generic start byte for a 2-byte sequence in UTF-8.
        char input[] = { 'A', (char)0xC2, 0 }; 
        ByteBuffer in(input, 2);
        LogString out;

        // 2. execution:
        // this decoder is the default on WCHAR builds.
        CharsetDecoderPtr decoder = CharsetDecoder::getDefaultDecoder();
        
        // without fix: infinite loop.
        // with fix: detects the stall and breaks/returns error.
        decoder->decode(in, out);
        
        // 3. verify: We survived the call.
        LOGUNIT_ASSERT(true);
    }
#endif
	
};

LOGUNIT_TEST_SUITE_REGISTRATION(CharsetDecoderTestCase);
