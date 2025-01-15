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

#include "../appenderskeletontestcase.h"
#include <log4cxx/patternlayout.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/net/xmlsocketappender.h>
#include <log4cxx/helpers/serversocket.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/private/aprsocket.h>
#include <apr_network_io.h>

namespace LOG4CXX_NS { namespace net {
	using SocketAppender = XMLSocketAppender;
} }

using namespace LOG4CXX_NS;

/**
   Unit tests of log4cxx::SocketAppender
 */
class SocketAppenderTestCase : public AppenderSkeletonTestCase
{
		LOGUNIT_TEST_SUITE(SocketAppenderTestCase);
		//
		//    tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);
		LOGUNIT_TEST(testRetryConnect);

		LOGUNIT_TEST_SUITE_END();


	public:

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new log4cxx::net::SocketAppender();
		}

		void testRetryConnect()
		{
			int tcpPort = 44445;
			auto appender = std::make_shared<net::SocketAppender>();
			appender->setLayout(std::make_shared<log4cxx::PatternLayout>(LOG4CXX_STR("%d [%T] %m%n")));
			appender->setRemoteHost(LOG4CXX_STR("localhost"));
			appender->setReconnectionDelay(100); // milliseconds
			appender->setPort(tcpPort);
			helpers::Pool pool;
			appender->activateOptions(pool);

			BasicConfigurator::configure(appender);
			auto logger = Logger::getLogger("test");
			int logEventCount = 3000;
			auto doLogging = [logger, logEventCount]()
			{
				apr_sleep(50000);    // 50 millisecond
				for( int x = 0; x < logEventCount; x++ ){
					LOG4CXX_INFO(logger, "Message " << x);
				}
			};
			std::vector<std::thread> loggingThread;
			for (auto i: {0, 1})
				loggingThread.emplace_back(doLogging);

			auto serverSocket = helpers::ServerSocket::create(tcpPort);
			serverSocket->setSoTimeout(1000); // milliseconds
			helpers::SocketPtr incomingSocket;
			try
			{
				incomingSocket = serverSocket->accept();
			}
			catch (std::exception& )
			{
				LOGUNIT_FAIL("accept failed");
			}
			auto aprSocket = dynamic_pointer_cast<helpers::APRSocket>(incomingSocket);
			LOGUNIT_ASSERT(aprSocket);
			auto pSocket = aprSocket->getSocketPtr();
			LOGUNIT_ASSERT(pSocket);
			apr_socket_timeout_set(pSocket, 100000);    // 100 millisecond
			std::vector<int> messageCount;
			char buffer[8*1024];
			apr_size_t len = sizeof(buffer);
			while (APR_SUCCESS == apr_socket_recv(pSocket, buffer, &len))
			{
				auto pStart = &buffer[0];
				auto pEnd = buffer + len;
				for (auto pChar = pStart; pChar < pEnd; ++pChar)
				{
					if ('\n' == *pChar)
					{
						std::string line(pStart, pChar);
						auto pos = line.rfind(' ');
						if (line.npos != pos && pos + 1 < line.size())
						{
							try
							{
								auto msgNumber = std::stoi(line.substr(pos));
								if (messageCount.size() <= msgNumber)
									messageCount.resize(msgNumber + 1);
								++messageCount[msgNumber];
							}
							catch (std::exception const& ex)
							{
								LogString msg;
								helpers::Transcoder::decode(ex.what(), msg);
								msg += LOG4CXX_STR(" processing\n");
								helpers::Transcoder::decode(line, msg);
								helpers::LogLog::warn(msg);
							}
						}
						pStart = pChar + 1;
					}
				}
				len = sizeof(buffer);
			}
			incomingSocket->close();
			for (auto& t : loggingThread)
				t.join();

			if (helpers::LogLog::isDebugEnabled())
			{
				helpers::Pool p;
				LogString msg(LOG4CXX_STR("messageCount "));
				for (auto item : messageCount)
				{
					msg += logchar(' ');
					helpers::StringHelper::toString(item, p, msg);
				}
				helpers::LogLog::debug(msg);
			}
			LOGUNIT_ASSERT_EQUAL(logEventCount, (int)messageCount.size());
		}
};

LOGUNIT_TEST_SUITE_REGISTRATION(SocketAppenderTestCase);
