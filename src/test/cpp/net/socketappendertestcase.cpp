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

#include <log4cxx/net/socketappender.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/helpers/serversocket.h>
#include "../appenderskeletontestcase.h"
#include "apr.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

#if APR_HAS_THREADS
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
		LOGUNIT_TEST(testInvalidHost);

		LOGUNIT_TEST_SUITE_END();


	public:

		void setUp()
		{
		}

		void tearDown()
		{
			BasicConfigurator::resetConfiguration();
		}

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new log4cxx::net::SocketAppender();
		}

		void testInvalidHost(){
//			log4cxx::net::SocketAppenderPtr appender = std::make_shared<log4cxx::net::SocketAppender>();
//			log4cxx::PatternLayoutPtr layout = std::make_shared<log4cxx::PatternLayout>(LOG4CXX_STR("%m%n"));

//			log4cxx::helpers::ServerSocket serverSocket(4445);

//			appender->setLayout(layout);
//			appender->setRemoteHost(LOG4CXX_STR("localhost"));
//			appender->setReconnectionDelay(1);
//			appender->setPort(4445);
//			log4cxx::helpers::Pool pool;
//			appender->activateOptions(pool);

//			BasicConfigurator::configure(appender);

//			log4cxx::Logger::getRootLogger()->setLevel(log4cxx::Level::getAll());

//			std::thread th1( [](){
//				for( int x = 0; x < 3000; x++ ){
//					LOG4CXX_INFO(Logger::getLogger(LOG4CXX_STR("test")), "Some message" );
//				}
//			});
//			std::thread th2( [](){
//				for( int x = 0; x < 3000; x++ ){
//					LOG4CXX_INFO(Logger::getLogger(LOG4CXX_STR("test")), "Some message" );
//				}
//			});

//			SocketPtr incomingSocket = serverSocket.accept();
//			incomingSocket->close();

//			// If we do not get here, we have deadlocked
//			th1.join();
//			th2.join();
		}
};

LOGUNIT_TEST_SUITE_REGISTRATION(SocketAppenderTestCase);
#endif
