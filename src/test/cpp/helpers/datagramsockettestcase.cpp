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
#include <log4cxx/helpers/datagramsocket.h>
#include <log4cxx/helpers/datagrampacket.h>
#include <log4cxx/helpers/inetaddress.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

LOGUNIT_CLASS(DatagramSocketTestCase)
{
	LOGUNIT_TEST_SUITE(DatagramSocketTestCase);
	LOGUNIT_TEST(testSendHonorsOffset);
	LOGUNIT_TEST(testReceiveHonorsOffset);
	LOGUNIT_TEST(testReceiveUpdatesLength);
	LOGUNIT_TEST_SUITE_END();

public:
	void testSendHonorsOffset()
	{
		int port = 45678;
		auto receiver = DatagramSocket::create(port);
		auto sender = DatagramSocket::create();
		auto addr = InetAddress::getByName(LOG4CXX_STR("127.0.0.1"));
		
		char buf[] = "ABCDEFGHIJ";
		// Packet with offset 3, length 5 should transmit "DEFGH"
		auto packet = std::make_shared<DatagramPacket>(buf, 3, 5, addr, port);
		sender->send(packet);
		
		char recvBuf[11] = {0};
		// Must provide address to avoid crash in receive()
		auto recvPacket = std::make_shared<DatagramPacket>(recvBuf, 10, addr, port);
		receiver->receive(recvPacket);
		
		LOGUNIT_ASSERT_EQUAL(std::string("DEFGH"), std::string(recvBuf, 5));
	}

	void testReceiveHonorsOffset()
	{
		int port = 45679;
		auto receiver = DatagramSocket::create(port);
		auto sender = DatagramSocket::create();
		auto addr = InetAddress::getByName(LOG4CXX_STR("127.0.0.1"));
		
		char sendBuf[] = "WXYZ";
		auto sendPacket = std::make_shared<DatagramPacket>(sendBuf, 4, addr, port);
		sender->send(sendPacket);
		
		char recvBuf[11] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		// Packet with offset 2, length 4 should write "WXYZ" starting at index 2
		auto recvPacket = std::make_shared<DatagramPacket>(recvBuf, 2, 4, addr, port);
		receiver->receive(recvPacket);
		
		LOGUNIT_ASSERT_EQUAL((char)0, recvBuf[0]);
		LOGUNIT_ASSERT_EQUAL((char)0, recvBuf[1]);
		LOGUNIT_ASSERT_EQUAL('W', recvBuf[2]);
		LOGUNIT_ASSERT_EQUAL('X', recvBuf[3]);
		LOGUNIT_ASSERT_EQUAL('Y', recvBuf[4]);
		LOGUNIT_ASSERT_EQUAL('Z', recvBuf[5]);
	}

	void testReceiveUpdatesLength()
	{
		int port = 45680;
		auto receiver = DatagramSocket::create(port);
		auto sender = DatagramSocket::create();
		auto addr = InetAddress::getByName(LOG4CXX_STR("127.0.0.1"));
		
		char sendBuf[] = "SHORT";
		auto sendPacket = std::make_shared<DatagramPacket>(sendBuf, 5, addr, port);
		sender->send(sendPacket);
		
		char recvBuf[100];
		auto recvPacket = std::make_shared<DatagramPacket>(recvBuf, 100, addr, port);
		receiver->receive(recvPacket);
		
		LOGUNIT_ASSERT_EQUAL(5, recvPacket->getLength());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(DatagramSocketTestCase);
