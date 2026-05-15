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

#include <log4cxx/asyncappender.h>

#include <atomic>
#include <memory>
#include <thread>

using namespace log4cxx;

LOGUNIT_CLASS(AsyncAppenderRaceStressTestCase)
{
	LOGUNIT_TEST_SUITE(AsyncAppenderRaceStressTestCase);
	LOGUNIT_TEST(raceGetSetBufferSize);
	LOGUNIT_TEST(raceGetSetBlocking);
	LOGUNIT_TEST_SUITE_END();

public:
	// This test is intentionally simple:
	// - it creates concurrent overlap between a setter (writes under bufferMutex) and a getter (read),
	// - it relies on ThreadSanitizer to prove the data race in the unsynchronized implementation,
	// - it is bounded, deterministic, and does not depend on timing sleeps or logging side effects.
	//
	// Expected behavior:
	// - With unsynchronized getters, ThreadSanitizer reports data races involving getBufferSize/getBlocking.
	// - With getters protected by bufferMutex, ThreadSanitizer is clean.
	void raceGetSetBufferSize()
	{
		auto async = std::make_shared<AsyncAppender>();
		async->setName(LOG4CXX_STR("AsyncAppenderRaceStress"));

		std::atomic<int> ready{ 0 };
		std::atomic<bool> start{ false };

		std::thread writer([&]()
		{
			ready.fetch_add(1, std::memory_order_release);
			while (!start.load(std::memory_order_acquire)) {}
			// Toggle between 1 and 2 to avoid exercising allocator behavior; we only want the data race.
			for (int i = 0; i < 200000; ++i)
			{
				async->setBufferSize((i & 1) + 1);
			}
		});

		std::thread reader([&]()
		{
			ready.fetch_add(1, std::memory_order_release);
			while (!start.load(std::memory_order_acquire)) {}
			for (int i = 0; i < 200000; ++i)
			{
				(void)async->getBufferSize();
			}
		});

		while (ready.load(std::memory_order_acquire) != 2) {}
		start.store(true, std::memory_order_release);

		writer.join();
		reader.join();
	 }

	void raceGetSetBlocking()
	{
		auto async = std::make_shared<AsyncAppender>();
		async->setName(LOG4CXX_STR("AsyncAppenderRaceStressBlocking"));

		std::atomic<int> ready{ 0 };
		std::atomic<bool> start{ false };

		std::thread writer([&]()
		{
			ready.fetch_add(1, std::memory_order_release);
			while (!start.load(std::memory_order_acquire)) {}
			for (int i = 0; i < 200000; ++i)
			{
				async->setBlocking((i & 1) != 0);
			}
		});

		std::thread reader([&]()
		{
			ready.fetch_add(1, std::memory_order_release);
			while (!start.load(std::memory_order_acquire)) {}
			for (int i = 0; i < 200000; ++i)
			{
				(void)async->getBlocking();
			}
		});

		while (ready.load(std::memory_order_acquire) != 2) {}
		start.store(true, std::memory_order_release);

		writer.join();
		reader.join();
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(AsyncAppenderRaceStressTestCase);
