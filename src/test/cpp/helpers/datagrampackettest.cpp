/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
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
#include <log4cxx/helpers/datagrampacket.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx::helpers;

LOGUNIT_CLASS(DatagramPacketTest)
{
	LOGUNIT_TEST_SUITE(DatagramPacketTest);
	LOGUNIT_TEST_EXCEPTION(testConstructorRejectsNegativeLength, IllegalArgumentException);
	LOGUNIT_TEST_EXCEPTION(testConstructorRejectsNegativeOffset, IllegalArgumentException);
	LOGUNIT_TEST_EXCEPTION(testConstructorRejectsNullBufferForNonEmptyPacket, NullPointerException);
	LOGUNIT_TEST_EXCEPTION(testSetDataRejectsNegativeLength, IllegalArgumentException);
	LOGUNIT_TEST_EXCEPTION(testSetLengthRejectsNegativeLength, IllegalArgumentException);
	LOGUNIT_TEST(testZeroLengthPacketAllowsNullBuffer);
	LOGUNIT_TEST_SUITE_END();

public:
	void testConstructorRejectsNegativeLength()
	{
		char buffer[1];
		DatagramPacket packet(buffer, -1);
	}

	void testConstructorRejectsNegativeOffset()
	{
		char buffer[1];
		DatagramPacket packet(buffer, -1, 1);
	}

	void testConstructorRejectsNullBufferForNonEmptyPacket()
	{
		DatagramPacket packet(nullptr, 1);
	}

	void testSetDataRejectsNegativeLength()
	{
		char buffer[1];
		DatagramPacket packet(buffer, 1);
		packet.setData(buffer, 0, -1);
	}

	void testSetLengthRejectsNegativeLength()
	{
		char buffer[1];
		DatagramPacket packet(buffer, 1);
		packet.setLength(-1);
	}

	void testZeroLengthPacketAllowsNullBuffer()
	{
		DatagramPacket packet(nullptr, 0);
		LOGUNIT_ASSERT_EQUAL(0, packet.getLength());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(DatagramPacketTest);
