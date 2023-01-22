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
#include "testchar.h"
#include "util/compare.h"
#include "util/transformer.h"
#include "util/absolutedateandtimefilter.h"
#include "util/iso8601filter.h"
#include "util/absolutetimefilter.h"
#include "util/relativetimefilter.h"
#include "util/controlfilter.h"
#include "util/threadfilter.h"
#include "util/linenumberfilter.h"
#include "util/filenamefilter.h"
#include "vectorappender.h"
#include <log4cxx/fmtlayout.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/date.h>
#include <log4cxx/spi/loggingevent.h>
#include <iostream>
#include <iomanip>

#define REGEX_STR(x) x
#define PAT0 REGEX_STR("\\[[0-9A-FXx]*]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - Message [0-9]\\{1,2\\}")
#define PAT1 ISO8601_PAT REGEX_STR(" ") PAT0
#define PAT2 ABSOLUTE_DATE_AND_TIME_PAT REGEX_STR(" ") PAT0
#define PAT3 ABSOLUTE_TIME_PAT REGEX_STR(" ") PAT0
#define PAT4 RELATIVE_TIME_PAT REGEX_STR(" ") PAT0
#define PAT5 REGEX_STR("\\[[0-9A-FXx]*]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* : Message [0-9]\\{1,2\\}")
#define PAT6 REGEX_STR("\\[[0-9A-FXx]*]\\ (DEBUG|INFO |WARN |ERROR|FATAL) .*patternlayouttest.cpp\\([0-9]\\{1,4\\}\\): Message [0-9]\\{1,3\\}")
#define PAT11a REGEX_STR("^(DEBUG|INFO |WARN |ERROR|FATAL) \\[[0-9A-FXx]*]\\ log4j.PatternLayoutTest: Message [0-9]\\{1,2\\}")
#define PAT11b REGEX_STR("^(DEBUG|INFO |WARN |ERROR|FATAL) \\[[0-9A-FXx]*]\\ root: Message [0-9]\\{1,2\\}")
#define PAT12 REGEX_STR("^\\[[0-9A-FXx]*]\\ (DEBUG|INFO |WARN |ERROR|FATAL) ")\
	REGEX_STR(".*patternlayouttest.cpp([0-9]\\{1,4\\}): ")\
	REGEX_STR("Message [0-9]\\{1,2\\}")
#define PAT_MDC_1 REGEX_STR("")

using namespace log4cxx;
using namespace log4cxx::helpers;

LOGUNIT_CLASS(FMTTestCase)
{
	LOGUNIT_TEST_SUITE(FMTTestCase);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test1_expanded);
	LOGUNIT_TEST(test10);
//	LOGUNIT_TEST(test_date);
	LOGUNIT_TEST_SUITE_END();

	LoggerPtr root;
	LoggerPtr logger;

public:
	void setUp()
	{
		root = Logger::getRootLogger();
		MDC::clear();
		logger = Logger::getLogger(LOG4CXX_TEST_STR("java.org.apache.log4j.PatternLayoutTest"));
	}

	void tearDown()
	{
		MDC::clear();
		auto rep = root->getLoggerRepository();

		if (rep)
		{
			rep->resetConfiguration();
		}
	}

	void test1()
	{
		PropertyConfigurator::configure(LOG4CXX_FILE("input/fmtLayout1.properties"));
		common();
		LOGUNIT_ASSERT(Compare::compare(TEMP, LOG4CXX_FILE("witness/patternLayout.1")));
	}

	void test1_expanded()
	{
		PropertyConfigurator::configure(LOG4CXX_FILE("input/fmtLayout1_expanded.properties"));
		common();
		LOGUNIT_ASSERT(Compare::compare(TEMP, LOG4CXX_FILE("witness/patternLayout.1")));
	}

	void test10()
	{
		PropertyConfigurator::configure(LOG4CXX_FILE("input/fmtLayout10.properties"));
		common();

		ControlFilter filter1;
		filter1 << PAT6;
		ThreadFilter filter2;
		LineNumberFilter filter3;
		FilenameFilter filenameFilter(__FILE__, "patternlayouttest.cpp");


		std::vector<Filter*> filters;
		filters.push_back(&filenameFilter);
		filters.push_back(&filter1);
		filters.push_back(&filter2);
		filters.push_back(&filter3);


		try
		{
			Transformer::transform(TEMP, FILTERED, filters);
		}
		catch (UnexpectedFormatException& e)
		{
			std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
			throw;
		}

		LOGUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/patternLayout.10")));
	}

	void test_date(){
		std::tm tm = {};
		std::stringstream ss("2013-04-11 08:35:34");
		ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
		auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
		uint64_t micros = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count();

		log4cxx::helpers::Date::setGetCurrentTimeFunction([micros](){
			return micros;
		});

		log4cxx::spi::LoggingEventPtr logEvt = std::make_shared<log4cxx::spi::LoggingEvent>(LOG4CXX_STR("foo"),
																							 Level::getInfo(),
																							 LOG4CXX_STR("A Message"),
																							 log4cxx::spi::LocationInfo::getLocationUnavailable());
		FMTLayout layout(LOG4CXX_STR("{d:%Y-%m-%d %H:%M:%S} {message}"));
		LogString output;
		log4cxx::helpers::Pool pool;
		layout.format( output, logEvt, pool);

		log4cxx::helpers::Date::setGetCurrentTimeFunction(nullptr);

		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("2013-04-11 09:35:34 A Message"), output);
	}

	std::string createMessage(Pool & pool, int i)
	{
		std::string msg("Message ");
		msg.append(pool.itoa(i));
		return msg;
	}

	void common()
	{
		int i = -1;

		Pool pool;


		LOG4CXX_DEBUG(logger, createMessage(pool, ++i));
		LOG4CXX_DEBUG(root, createMessage(pool, i));

		LOG4CXX_INFO(logger, createMessage(pool, ++i));
		LOG4CXX_INFO(root, createMessage(pool, i));

		LOG4CXX_WARN(logger, createMessage(pool, ++i));
		LOG4CXX_WARN(root, createMessage(pool, i));

		LOG4CXX_ERROR(logger, createMessage(pool, ++i));
		LOG4CXX_ERROR(root, createMessage(pool, i));

		LOG4CXX_FATAL(logger, createMessage(pool, ++i));
		LOG4CXX_FATAL(root, createMessage(pool, i));
	}

	private:
		static const LogString FILTERED;
		static const LogString TEMP;

};

const LogString FMTTestCase::TEMP(LOG4CXX_STR("output/fmtlayout"));
const LogString FMTTestCase::FILTERED(LOG4CXX_STR("output/fmtlayoutfiltered"));


LOGUNIT_TEST_SUITE_REGISTRATION(FMTTestCase);
