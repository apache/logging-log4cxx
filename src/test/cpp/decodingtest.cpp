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


#include <string>

#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/helpers/inputstreamreader.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/logstring.h>

#include "logunit.h"
//
// If there is no support for wchar_t logging then
// there is not a consistent way to get the test characters compared.
//
#if LOG4CXX_WCHAR_T_API

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
 * Tests support for decoding specification.
 *
 * The lib provides multiple different decoders and decides which to use by default on compile time.
 * This test uses the same checks like {@link CharsetDecoder#createDefaultDecoder} to decide which
 * checks to run actually, so that some input file with some encoded text according to the decoder
 * in use is read and the contents compared to some witness. Because of different decoders not all
 * files have the same content, e.g. the ASCII-only decoder can't deal with Unicode chars obviously.
 *
 * This test is based on encodingtest and uses that witnesses, especially the hard coded strings for
 * greeting and pi. We only combine it into one in the former mentioned order, divided by a space.
 *
 * @see LOGCXX-369
 * @see LOGCXX-399
 */
LOGUNIT_CLASS(DecodingTest)
{
	LOGUNIT_TEST_SUITE(DecodingTest);
#if LOG4CXX_CHARSET_USASCII
	LOGUNIT_TEST(testASCII);
#elif LOG4CXX_CHARSET_ISO88591 || defined(_WIN32_WCE)
	LOGUNIT_TEST(testLatin1);
#elif LOG4CXX_CHARSET_UTF8
	LOGUNIT_TEST(testUtf8);
#elif LOG4CXX_LOGCHAR_IS_WCHAR && LOG4CXX_HAS_MBSRTOWCS
	LOGUNIT_TEST(testUtf16);
	LOGUNIT_TEST(testUtf16LE);
	LOGUNIT_TEST(testUtf16BE);
#else
	// LocaleCharsetDecoder, so it's difficult to provide a file working for e.g. windows-1252
	// as well as something completely different.
	LOGUNIT_TEST(testASCII);
#endif
	LOGUNIT_TEST_SUITE_END();
public:
	/**
	 * Test us-ascii decoding.
	 */
	void testASCII()
	{
		const wchar_t witness[] = { L'A', 0x003F, 0x003F, 0x003F, 0x003F, 0x003F, 0x0020, 0x003F, 0 };

		testImpl(LOG4CXX_STR("ascii.txt"), witness);

	}

	/**
	 * Test iso-8859-1 decoding.
	 */
	void testLatin1()
	{
		const wchar_t witness[] = { L'A', 0x003F, 0x003F, 0x003F, 0x003F, 0x003F, 0x0020, 0x00B9, 0 };

		testImpl(LOG4CXX_STR("latin1.txt"), witness);
	}

	/**
	 * Test utf-8 decoding.
	 */
	void testUtf8()
	{
		const wchar_t witness[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x0400, 0x0020, 0x00B9, 0 };

		testImpl(LOG4CXX_STR("UTF-8.txt"), witness);
	}

	/**
	 * Test utf-16 decoding.
	 */
	void testUtf16()
	{
		const wchar_t witness[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x0400, 0x0020, 0x00B9, 0 };

		testImpl(LOG4CXX_STR("UTF-16.txt"), witness);
	}

	/**
	 * Test utf-16be decoding.
	 */
	void testUtf16BE()
	{
		const wchar_t witness[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x0400, 0x0020, 0x00B9, 0 };

		testImpl(LOG4CXX_STR("UTF-16BE.txt"), witness);
	}

	/**
	 * Test utf16-le decoding.
	 */
	void testUtf16LE()
	{
		const wchar_t witness[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x0400, 0x0020, 0x00B9, 0 };

		testImpl(LOG4CXX_STR("UTF-16LE.txt"), witness);
	}

private:
	void testImpl(
		const LogString & fileName,
		const wchar_t*   witness)
	{
		CharsetDecoderPtr decoder(CharsetDecoder::getDefaultDecoder());
		LogString         lsContent;
		std::wstring      wsContent;
		LogString         path(LOG4CXX_STR("input/decoding/") + fileName);
		Pool              pool;

		FileInputStreamPtr   fis(     new FileInputStream(path));
		InputStreamReaderPtr isReader(new InputStreamReader(fis, decoder));

		lsContent.assign(isReader->read(pool));
		Transcoder::encode(lsContent, wsContent);

		LOGUNIT_ASSERT_EQUAL((std::wstring) witness, wsContent);
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(DecodingTest);

#endif

