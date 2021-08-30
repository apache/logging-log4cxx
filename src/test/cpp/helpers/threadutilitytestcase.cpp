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
#include <log4cxx/helpers/threadutility.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


LOGUNIT_CLASS(ThreadUtilityTest)
{
	LOGUNIT_TEST_SUITE(ThreadUtilityTest);
	LOGUNIT_TEST(testNullFunctions);
	LOGUNIT_TEST(testCustomFunctions);
	LOGUNIT_TEST(testDefaultFunctions);
	LOGUNIT_TEST_SUITE_END();

public:
	void testNullFunctions(){
		ThreadUtilityPtr thrUtil = ThreadUtility::instance();

		thrUtil->configureFuncs( nullptr, nullptr, nullptr );

		std::thread t = thrUtil->createThread( LOG4CXX_STR("FooName"), [](){} );

		t.join();
	}

	void testCustomFunctions(){
		ThreadUtilityPtr thrUtil = ThreadUtility::instance();
		int num_pre = 0;
		int num_started = 0;
		int num_post = 0;

		thrUtil->configureFuncs(
			[&num_pre](){
				num_pre++;
			},
			[&num_started]( LogString,
							std::thread::id,
							std::thread::native_handle_type ){
				num_started++;
			},
			[&num_post](){
				num_post++;
			}
		);

		std::thread t = thrUtil->createThread( LOG4CXX_STR("FooName"), [](){} );

		t.join();

		LOGUNIT_ASSERT_EQUAL( num_pre, 1 );
		LOGUNIT_ASSERT_EQUAL( num_started, 1 );
		LOGUNIT_ASSERT_EQUAL( num_post, 1 );
	}

	void testDefaultFunctions(){
		ThreadUtility::configure( ThreadConfigurationType::BlockSignalsAndNameThread );

		ThreadUtilityPtr thrUtil = ThreadUtility::instance();

		std::thread t = thrUtil->createThread( LOG4CXX_STR("FooName"), [](){} );

		t.join();
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(ThreadUtilityTest);

