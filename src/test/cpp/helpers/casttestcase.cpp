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

#include "../logunit.h"
#include <log4cxx/helpers/bytearrayoutputstream.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <iostream>

using namespace log4cxx;
using namespace log4cxx::helpers;

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>

/**
 */
LOGUNIT_CLASS(CastTestCase)
{
	LOGUNIT_TEST_SUITE( CastTestCase );
	LOGUNIT_TEST(testGoodCast);
	LOGUNIT_TEST(testBadCast);
	LOGUNIT_TEST(testNullParameter);
	LOGUNIT_TEST(testRollingFileAppender);
	LOGUNIT_TEST(testByteArrayOutputStreamWriteAfterDefaultConstruction);
	LOGUNIT_TEST(testByteArrayOutputStreamIgnoresEmptyWrite);
	LOGUNIT_TEST_SUITE_END();

public:

	/**
	 *
	 */
	void testGoodCast()
	{
		OutputStreamPtr out = OutputStreamPtr(new ByteArrayOutputStream());

		ByteArrayOutputStreamPtr byteOut = log4cxx::cast<ByteArrayOutputStream>(out);

		LOGUNIT_ASSERT(byteOut);
	}

	void testBadCast()
	{
		OutputStreamPtr out = OutputStreamPtr(new ByteArrayOutputStream());

		FileOutputStreamPtr fos = log4cxx::cast<FileOutputStream>(out);

		LOGUNIT_ASSERT(!fos);
	}

	void testNullParameter()
	{
		OutputStreamPtr out = nullptr;

		FileOutputStreamPtr fos = log4cxx::cast<FileOutputStream>(out);

		LOGUNIT_ASSERT(!fos);
	}

	void testRollingFileAppender()
	{
		rolling::RollingFileAppenderPtr rolling = rolling::RollingFileAppenderPtr(new rolling::RollingFileAppender());

		AppenderPtr appender = log4cxx::cast<Appender>(rolling);

		LOGUNIT_ASSERT(appender);
	}

	/**
	 * The default constructor of ByteArrayOutputStream left its private
	 * unique_ptr default-initialised (nullptr), so the first call into
	 * write() / toByteArray() dereferenced a null pointer. Verify that
	 * a freshly constructed instance can accept input and round-trip it
	 * back through toByteArray() without crashing.
	 */
	void testByteArrayOutputStreamWriteAfterDefaultConstruction()
	{
		ByteArrayOutputStreamPtr stream = std::make_shared<ByteArrayOutputStream>();

		char payload[] = { 'l', 'o', 'g', '4', 'c', 'x', 'x' };
		ByteBuffer buf(payload, sizeof(payload));

		stream->write(buf);

		ByteList result = stream->toByteArray();
		LOGUNIT_ASSERT_EQUAL(sizeof(payload), result.size());
		for (size_t i = 0; i < sizeof(payload); ++i)
		{
			LOGUNIT_ASSERT_EQUAL(static_cast<unsigned char>(payload[i]), result[i]);
		}
	}

	void testByteArrayOutputStreamIgnoresEmptyWrite()
	{
		ByteArrayOutputStreamPtr stream = std::make_shared<ByteArrayOutputStream>();

		char payload[] = { 'x' };
		ByteBuffer buf(payload, 0);

		stream->write(buf);

		LOGUNIT_ASSERT_EQUAL(size_t(0), stream->toByteArray().size());
		LOGUNIT_ASSERT_EQUAL(size_t(0), buf.remaining());
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(CastTestCase);
