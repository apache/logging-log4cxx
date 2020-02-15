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
#include <log4cxx/filter/denyallfilter.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/spi/loggingevent.h>
#include "../logunit.h"

using namespace log4cxx;
using namespace log4cxx::filter;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;


/**
 * Unit tests for DenyAllFilter.
 */
LOGUNIT_CLASS(DenyAllFilterTest)
{
	LOGUNIT_TEST_SUITE(DenyAllFilterTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST_SUITE_END();

public:
	/**
	 * Check that DenyAllFilter.decide() returns Filter.DENY.
	 */
	void test1()
	{
		LoggingEventPtr event(new LoggingEvent(
				LOG4CXX_STR("org.apache.log4j.filter.DenyAllFilterTest"),
				Level::getInfo(),
				LOG4CXX_STR("Hello, World"),
				LOG4CXX_LOCATION));
		FilterPtr filter(new DenyAllFilter());
		Pool p;
		filter->activateOptions(p);
		LOGUNIT_ASSERT_EQUAL(Filter::DENY, filter->decide(event));
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(DenyAllFilterTest);


