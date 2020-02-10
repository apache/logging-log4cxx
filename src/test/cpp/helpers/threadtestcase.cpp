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
#include <log4cxx/helpers/thread.h>
#include "../insertwide.h"
#include "../logunit.h"
#include <apr_time.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


/**
   Unit test for Thread.

   */
LOGUNIT_CLASS(ThreadTestCase)
{
	LOGUNIT_TEST_SUITE(ThreadTestCase);
	LOGUNIT_TEST(testInterrupt);
	LOGUNIT_TEST_SUITE_END();

public:
	/**
	 * Start a thread that will wait for a minute, then interrupt it.
	 */
	void testInterrupt()
	{
		Thread thread1;
		bool interrupted = false;
		thread1.run(sleep, &interrupted);
		apr_sleep(100000);
		apr_time_t start = apr_time_now();
		thread1.interrupt();
		thread1.join();
		LOGUNIT_ASSERT_EQUAL(true, interrupted);
		apr_time_t elapsed = apr_time_now() - start;
		LOGUNIT_ASSERT(elapsed < 1000000);
	}

private:
	static void* LOG4CXX_THREAD_FUNC sleep(apr_thread_t* thread, void* data)
	{
		try
		{
			Thread::sleep(60000);
		}
		catch (InterruptedException& ex)
		{
			*(reinterpret_cast<bool*>(data)) = true;
		}

		return NULL;
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(ThreadTestCase);

