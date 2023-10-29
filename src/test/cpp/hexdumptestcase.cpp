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

#include "logunit.h"
#include <log4cxx/hexdump.h>
#include <iostream>

using namespace LOG4CXX_NS;

LOGUNIT_CLASS(HexdumpTestCase)
{
	LOGUNIT_TEST_SUITE(HexdumpTestCase);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test_newline);
	LOGUNIT_TEST(test_newline2);
	LOGUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
	}

	void tearDown()
	{
	}

	void test1()
	{
		unsigned char test1_str[] = {
		  0x74, 0x65, 0x73, 0x74, 0x31
		};

		LogString expectedOutput =
				LOG4CXX_STR("00000000  74 65 73 74 31                                    |test1|");

		LogString dumped = LOG4CXX_NS::hexdump(test1_str, sizeof(test1_str));
		LOGUNIT_ASSERT_EQUAL(expectedOutput, dumped);
	}

	void test2()
	{
		unsigned char quick_brown_fox[] = {
		  0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72,
		  0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70,
		  0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c,
		  0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67
		};
		LogString expectedOutput =
				LOG4CXX_STR("00000000  54 68 65 20 71 75 69 63  6b 20 62 72 6f 77 6e 20  |The quick brown |")
				LOG4CXX_EOL
				LOG4CXX_STR("00000010  66 6f 78 20 6a 75 6d 70  73 20 6f 76 65 72 20 74  |fox jumps over t|")
				LOG4CXX_EOL
				LOG4CXX_STR("00000020  68 65 20 6c 61 7a 79 20  64 6f 67                 |he lazy dog|");

		// Hexdump up until the NULL char
		LogString dumped = LOG4CXX_NS::hexdump(quick_brown_fox, sizeof(quick_brown_fox));
		LOGUNIT_ASSERT_EQUAL(expectedOutput, dumped);
	}

	void test_newline()
	{
		unsigned char test1_str[] = {
		  0x74, 0x65, 0x73, 0x74, 0x31
		};
		LogString expectedOutput =
				LOG4CXX_EOL
				LOG4CXX_STR("00000000  74 65 73 74 31                                    |test1|")
				LOG4CXX_EOL;

		LogString dumped = LOG4CXX_NS::hexdump(test1_str, sizeof(test1_str), HexdumpFlags::AddNewline);
		LOGUNIT_ASSERT_EQUAL(expectedOutput, dumped);
	}

	void test_newline2()
	{
		unsigned char test1_str[] = {
		  0x74, 0x65, 0x73, 0x74, 0x31
		};
		LogString expectedOutput =
				LOG4CXX_EOL
				LOG4CXX_STR("00000000  74 65 73 74 31                                    |test1|")
				LOG4CXX_EOL;

		LogString dumped = LOG4CXX_NS::hexdump(test1_str, sizeof(test1_str), HexdumpFlags::AddStartingNewline | HexdumpFlags::AddEndingNewline);
		LOGUNIT_ASSERT_EQUAL(expectedOutput, dumped);
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(HexdumpTestCase);
