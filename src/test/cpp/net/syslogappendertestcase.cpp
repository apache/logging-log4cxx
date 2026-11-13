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

#define LOG4CXX_TEST 1
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
		LOGUNIT_TEST(testSyslogHostWithMalformedPort);
		LOGUNIT_TEST(testFormatOption);
		LOGUNIT_TEST(testRfc5424FieldOptions);
		LOGUNIT_TEST(testRfc5424Header);
		LOGUNIT_TEST(testRfc5424HeaderNilValues);

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

			LOGUNIT_ASSERT_EQUAL((size_t) 5, packets.size());
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

			LOGUNIT_ASSERT_EQUAL((size_t) 19999, packets.size());
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

			LOGUNIT_ASSERT_EQUAL((size_t) 770, packets.size());
			LOGUNIT_ASSERT_EQUAL(LogString(13, static_cast<logchar>('A')), packets.front());
			LOGUNIT_ASSERT_EQUAL(LogString(3, static_cast<logchar>('A')), packets.back());
			for (const auto& packet : packets)
			{
				LOGUNIT_ASSERT(packet.size() <= maxMessageLength);
				LOGUNIT_ASSERT(packet.find(LOG4CXX_STR("(")) == LogString::npos);
			}
		}

		/**
		 * A SyslogHost value with a port that is not an integer must not throw
		 * and must use the host name without the port.
		 */
		void testSyslogHostWithMalformedPort()
		{
			log4cxx::net::SyslogAppender appender;
			appender.setOption(LOG4CXX_STR("SyslogHost"), LOG4CXX_STR("127.0.0.1:"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("127.0.0.1"), appender.getSyslogHost());
			appender.setOption(LOG4CXX_STR("SyslogHost"), LOG4CXX_STR("127.0.0.1:udp"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("127.0.0.1"), appender.getSyslogHost());
			appender.setOption(LOG4CXX_STR("SyslogHost"), LOG4CXX_STR("127.0.0.1:99999999999"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("127.0.0.1"), appender.getSyslogHost());
		}

		/**
		 * The Format option accepts BSD and RFC5424 in any case
		 * and ignores an unknown value.
		 */
		void testFormatOption()
		{
			log4cxx::net::SyslogAppender appender;
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("BSD"), appender.getFormat());
			appender.setOption(LOG4CXX_STR("Format"), LOG4CXX_STR("rfc5424"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("RFC5424"), appender.getFormat());
			appender.setOption(LOG4CXX_STR("FORMAT"), LOG4CXX_STR("RFC3164"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("RFC5424"), appender.getFormat());
			appender.setOption(LOG4CXX_STR("format"), LOG4CXX_STR("Bsd"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("BSD"), appender.getFormat());
		}

		/**
		 * The AppName and MessageId options are made valid RFC 5424 header fields.
		 */
		void testRfc5424FieldOptions()
		{
			log4cxx::net::SyslogAppender appender;
			LOGUNIT_ASSERT(appender.getAppName().empty());
			LOGUNIT_ASSERT(appender.getMessageId().empty());

			appender.setOption(LOG4CXX_STR("AppName"), LOG4CXX_STR("myapp"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("myapp"), appender.getAppName());
			appender.setOption(LOG4CXX_STR("AppName"), LOG4CXX_STR("my app\t1"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("my_app_1"), appender.getAppName());
			appender.setOption(LOG4CXX_STR("AppName"), LogString(60, static_cast<logchar>('a')));
			LOGUNIT_ASSERT_EQUAL(LogString(48, static_cast<logchar>('a')), appender.getAppName());
			appender.setOption(LOG4CXX_STR("AppName"), LogString());
			LOGUNIT_ASSERT(appender.getAppName().empty());

			appender.setOption(LOG4CXX_STR("MessageId"), LOG4CXX_STR("ID47"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("ID47"), appender.getMessageId());
			appender.setOption(LOG4CXX_STR("MessageId"), LOG4CXX_STR("ID 47"));
			LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("ID_47"), appender.getMessageId());
			appender.setOption(LOG4CXX_STR("MessageId"), LogString(40, static_cast<logchar>('m')));
			LOGUNIT_ASSERT_EQUAL(LogString(32, static_cast<logchar>('m')), appender.getMessageId());
		}

		/**
		 * The RFC 5424 header has a UTC timestamp with microsecond precision.
		 */
		void testRfc5424Header()
		{
			// 2003-10-11T22:14:15.003210Z
			const log4cxx_time_t timestamp = 1065910455003210LL;
			LogString header(LOG4CXX_STR("<34>"));
			log4cxx::net::detail::appendRfc5424Header(header, timestamp,
				LOG4CXX_STR("mymachine.example.com"), LOG4CXX_STR("su"),
				LOG4CXX_STR("4321"), LOG4CXX_STR("ID47"));
			LOGUNIT_ASSERT_EQUAL((LogString)
				LOG4CXX_STR("<34>1 2003-10-11T22:14:15.003210Z mymachine.example.com su 4321 ID47 - "),
				header);
		}

		/**
		 * An empty RFC 5424 header field is sent as the nil value.
		 */
		void testRfc5424HeaderNilValues()
		{
			LogString header;
			log4cxx::net::detail::appendRfc5424Header(header, 0,
				LogString(), LogString(), LogString(), LogString());
			LOGUNIT_ASSERT_EQUAL((LogString)
				LOG4CXX_STR("1 1970-01-01T00:00:00.000000Z - - - - - "),
				header);
		}

};

LOGUNIT_TEST_SUITE_REGISTRATION(SyslogAppenderTestCase);
