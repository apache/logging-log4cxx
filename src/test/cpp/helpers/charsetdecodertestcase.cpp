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
#include "../logunit.h"
#include "../insertwide.h"
#include <log4cxx/helpers/bytebuffer.h>

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


};

LOGUNIT_TEST_SUITE_REGISTRATION(CharsetDecoderTestCase);
