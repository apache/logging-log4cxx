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

#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/net/syslogappender.h>
#include <log4cxx/private/syslogappender_priv.h>
#include "../appenderskeletontestcase.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   Unit tests of log4cxx::SyslogAppender
 */
class SyslogAppenderTestCase : public AppenderSkeletonTestCase
{
		LOGUNIT_TEST_SUITE(SyslogAppenderTestCase);
		//
		//    tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);
		LOGUNIT_TEST(testSetMaxMessageLengthBelowSuffixSizeFallsBack);
		LOGUNIT_TEST(testSetMaxMessageLengthNegativeFallsBack);
		LOGUNIT_TEST(testMaxMessageLengthOptionBelowSuffixSizeFallsBack);
		LOGUNIT_TEST(testMaxMessageLengthOptionValid);
		LOGUNIT_TEST(testSplitMessageOneByteRemainderBoundary);
		LOGUNIT_TEST(testImpossibleSuffixFitHandling);
		LOGUNIT_TEST(testDigitGrowthBoundaryCase);

		LOGUNIT_TEST_SUITE_END();


	public:

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new log4cxx::net::SyslogAppender();
		}

	private:
		static LogString makePacket(size_t payloadLength, size_t current, size_t total)
		{
			LogString packet(payloadLength, static_cast<logchar>('A'));
			packet.append(LOG4CXX_STR("("));
			StringHelper::toString(current, packet);
			packet.append(LOG4CXX_STR("/"));
			StringHelper::toString(total, packet);
			packet.append(LOG4CXX_STR(")"));
			return packet;
		}

		void testSetMaxMessageLengthBelowSuffixSizeFallsBack()
		{
			log4cxx::net::SyslogAppender appender;
			appender.setMaxMessageLength(12);
			LOGUNIT_ASSERT(appender.getMaxMessageLength() >= 13);
		}

		void testSetMaxMessageLengthNegativeFallsBack()
		{
			log4cxx::net::SyslogAppender appender;
			appender.setMaxMessageLength(-100);
			LOGUNIT_ASSERT(appender.getMaxMessageLength() >= 13);
		}

		void testMaxMessageLengthOptionBelowSuffixSizeFallsBack()
		{
			log4cxx::net::SyslogAppender appender;
			appender.setOption(LOG4CXX_STR("MAXMESSAGELENGTH"), LOG4CXX_STR("5"));
			LOGUNIT_ASSERT(appender.getMaxMessageLength() >= 13);
		}

		void testMaxMessageLengthOptionValid()
		{
			log4cxx::net::SyslogAppender appender;
			appender.setOption(LOG4CXX_STR("MAXMESSAGELENGTH"), LOG4CXX_STR("2048"));
			LOGUNIT_ASSERT_EQUAL(2048, appender.getMaxMessageLength());
		}

		void testSplitMessageOneByteRemainderBoundary()
		{
			const size_t maxMessageLength = 16u;
			const LogString message(17, static_cast<logchar>('A'));
			const auto packets = log4cxx::net::detail::splitSyslogPackets(message, maxMessageLength);

			LOGUNIT_ASSERT_EQUAL(5U, packets.size());
			LOGUNIT_ASSERT_EQUAL(makePacket(4u, 1u, 5u), packets[0]);
			LOGUNIT_ASSERT_EQUAL(makePacket(4u, 2u, 5u), packets[1]);
			LOGUNIT_ASSERT_EQUAL(makePacket(4u, 3u, 5u), packets[2]);
			LOGUNIT_ASSERT_EQUAL(makePacket(4u, 4u, 5u), packets[3]);
			LOGUNIT_ASSERT_EQUAL(makePacket(1u, 5u, 5u), packets[4]);
			for (const auto& packet : packets)
			{
				LOGUNIT_ASSERT(packet.size() <= maxMessageLength);
			}
		}

		void testDigitGrowthBoundaryCase()
		{
			const size_t maxMessageLength = 14u;
			const LogString message(19999, static_cast<logchar>('A'));
			const auto packets = log4cxx::net::detail::splitSyslogPackets(message, maxMessageLength);

			LOGUNIT_ASSERT_EQUAL(19999U, packets.size());
			LOGUNIT_ASSERT_EQUAL(makePacket(1u, 1u, 19999u), packets.front());
			LOGUNIT_ASSERT_EQUAL(makePacket(1u, 9999u, 19999u), packets[9998]);
			LOGUNIT_ASSERT_EQUAL(makePacket(1u, 10000u, 19999u), packets[9999]);
			LOGUNIT_ASSERT_EQUAL(makePacket(1u, 19999u, 19999u), packets.back());
			LOGUNIT_ASSERT(packets.front().size() <= maxMessageLength);
			LOGUNIT_ASSERT(packets[9998].size() <= maxMessageLength);
			LOGUNIT_ASSERT(packets[9999].size() <= maxMessageLength);
			LOGUNIT_ASSERT(packets.back().size() <= maxMessageLength);
		}

		void testImpossibleSuffixFitHandling()
		{
			const size_t maxMessageLength = 13u;
			const LogString message(10000, static_cast<logchar>('A'));
			const auto packets = log4cxx::net::detail::splitSyslogPackets(message, maxMessageLength);

			LOGUNIT_ASSERT_EQUAL(770U, packets.size());
			LOGUNIT_ASSERT_EQUAL(LogString(13, static_cast<logchar>('A')), packets.front());
			LOGUNIT_ASSERT_EQUAL(LogString(3, static_cast<logchar>('A')), packets.back());
			for (const auto& packet : packets)
			{
				LOGUNIT_ASSERT(packet.size() <= maxMessageLength);
				LOGUNIT_ASSERT(packet.find(LOG4CXX_STR("(")) == LogString::npos);
			}
		}

};

LOGUNIT_TEST_SUITE_REGISTRATION(SyslogAppenderTestCase);
