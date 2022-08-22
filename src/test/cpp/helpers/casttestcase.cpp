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
#include <log4cxx/helpers/fileoutputstream.h>
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

};

LOGUNIT_TEST_SUITE_REGISTRATION(CastTestCase);
