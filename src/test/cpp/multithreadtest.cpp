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

#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/appenderskeleton.h>
#include <thread>
#include <vector>
#include <random>

using log4cxx::Logger;
using log4cxx::LoggerPtr;
using log4cxx::LogManager;

class NullWriterAppender : public log4cxx::AppenderSkeleton{
public:
	NullWriterAppender(){}

	virtual void close(){}

	virtual bool requiresLayout() const {
		return false;
	}

	virtual void append(const log4cxx::spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p){
		// Do nothing but discard the data
	}
};

static void multithread_logger( int times ){
	/*
	 * An explanation on this test: according to LOGCXX-322, calling
	 * exit(0) (or equivalent) from a secondary thread causes a segfault.
	 *
	 * In order to do this somewhat reliably, we generate a pseudo-random
	 * number in each thread that will call the exit() function from that thread.
	 * Sadly this is not a 100% reliable way of generating a hit on std::exit,
	 * but given enough iterations and enough threads it seems to be working just
	 * fine.
	 */

	LoggerPtr logger = LogManager::getLogger( "test.multithreaded" );
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> distribution( 100, times );

	for( int x = 0; x < times; x++ ){
		LOG4CXX_INFO( logger, "This is a test message that has some data" );
		if( distribution(gen) == x ){
			std::exit(0);
		}
	}
}

LOGUNIT_CLASS(MultithreadTest){
	LOGUNIT_TEST_SUITE(MultithreadTest);
	LOGUNIT_TEST(testMultithreadedLoggers);
	LOGUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
		Logger::getRootLogger()->removeAllAppenders();
		std::shared_ptr<NullWriterAppender> nullWriter( new NullWriterAppender() );
		Logger::getRootLogger()->addAppender( nullWriter );
	}

	void tearDown()
	{
	}

	void testMultithreadedLoggers(){
		std::vector<std::thread> threads;

		for( int x = 0; x < 6; x++ ){
			std::thread thr( multithread_logger, 20000 );
			threads.push_back( std::move(thr) );
		}

		for( std::thread& thr : threads ){
			if( thr.joinable() ){
				thr.join();
			}
		}
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(MultithreadTest);
