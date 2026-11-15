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
#include <log4cxx/ecslayout.h>
#include <log4cxx/level.h>
#include <log4cxx/ndc.h>
#include <log4cxx/mdc.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/spi/loggingevent.h>

#include <apr_time.h>
#include <cstdio>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

/**
 * Tests for ECSLayout.
 */
LOGUNIT_CLASS(ECSLayoutTest)
{
	LOGUNIT_TEST_SUITE(ECSLayoutTest);
	LOGUNIT_TEST(testGetContentType);
	LOGUNIT_TEST(testIgnoresThrowable);
	LOGUNIT_TEST(testRegisteredClass);
	LOGUNIT_TEST(testSetOption);
	LOGUNIT_TEST(testEventDatasetDefault);
	LOGUNIT_TEST(testTimestamp);
	LOGUNIT_TEST(testFormat);
	LOGUNIT_TEST(testFormatWithServiceFields);
	LOGUNIT_TEST(testFormatWithContext);
	LOGUNIT_TEST(testFormatWithLocationInfo);
	LOGUNIT_TEST(testFormatWithoutAvailableLocationInfo);
	LOGUNIT_TEST_SUITE_END();

	LoggingEventPtr makeEvent
		( const LogString& message
		, const LocationInfo& location = LocationInfo::getLocationUnavailable()
		)
	{
		return std::make_shared<LoggingEvent>
			( LOG4CXX_STR("com.foo.Bar")
			, Level::getInfo()
			, message
			, location
			);
	}

	// The fields this layout always adds after the message
	LogString commonFields(const LoggingEventPtr& event)
	{
		return LOG4CXX_STR("\"ecs.version\":\"1.2.0\",\"log.logger\":\"com.foo.Bar\",\"process.thread.name\":\"")
			+ event->getThreadUserName() + LOG4CXX_STR("\"");
	}

	// The output expected before the common fields
	LogString leadingFields(const LoggingEventPtr& event, const LogString& message)
	{
		return LOG4CXX_STR("{\"@timestamp\":\"")
			+ expectedTimestamp(event)
			+ LOG4CXX_STR("\",\"log.level\":\"INFO\",\"message\":\"")
			+ message
			+ LOG4CXX_STR("\",");
	}

	// The event time in UTC computed without using a Log4cxx DateFormat
	LogString expectedTimestamp(const LoggingEventPtr& event)
	{
		apr_time_exp_t utc;
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, apr_time_exp_gmt(&utc, event->getTimeStamp()));
		char buf[64];
		std::snprintf(buf, sizeof (buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
			utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
			utc.tm_hour, utc.tm_min, utc.tm_sec, utc.tm_usec / 1000);
		LOG4CXX_DECODE_CHAR(result, std::string(buf));
		return result;
	}

public:
	void setUp()
	{
		NDC::clear();
		MDC::clear();
	}

	void tearDown()
	{
		setUp();
	}

	void testGetContentType()
	{
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("application/json"), ECSLayout().getContentType());
	}

	void testIgnoresThrowable()
	{
		LOGUNIT_ASSERT_EQUAL(false, ECSLayout().ignoresThrowable());
	}

	/**
	 * Tests the layout can be named in a configuration file.
	 */
	void testRegisteredClass()
	{
		auto& layoutClass = Class::forName(LOG4CXX_STR("org.apache.log4j.EcsLayout"));
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("ECSLayout"), layoutClass.getName());
		ObjectPtr instance(layoutClass.newInstance());
		LOGUNIT_ASSERT(log4cxx::cast<ECSLayout>(instance));
	}

	void testSetOption()
	{
		ECSLayout layout;
		LOGUNIT_ASSERT_EQUAL(false, layout.getLocationInfo());
		LOGUNIT_ASSERT(layout.getServiceName().empty());
		layout.setOption(LOG4CXX_STR("ServiceName"), LOG4CXX_STR("MyApp"));
		layout.setOption(LOG4CXX_STR("serviceversion"), LOG4CXX_STR("1.2.3"));
		layout.setOption(LOG4CXX_STR("SERVICEENVIRONMENT"), LOG4CXX_STR("production"));
		layout.setOption(LOG4CXX_STR("ServiceNodeName"), LOG4CXX_STR("node-1"));
		layout.setOption(LOG4CXX_STR("EventDataset"), LOG4CXX_STR("MyApp.ecs"));
		layout.setOption(LOG4CXX_STR("LocationInfo"), LOG4CXX_STR("true"));
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("MyApp"), layout.getServiceName());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("1.2.3"), layout.getServiceVersion());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("production"), layout.getServiceEnvironment());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("node-1"), layout.getServiceNodeName());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("MyApp.ecs"), layout.getEventDataset());
		LOGUNIT_ASSERT_EQUAL(true, layout.getLocationInfo());
	}

	/**
	 * Tests event.dataset is the service name unless set explicitly.
	 */
	void testEventDatasetDefault()
	{
		ECSLayout layout;
		LOGUNIT_ASSERT(layout.getEventDataset().empty());
		layout.setServiceName(LOG4CXX_STR("MyApp"));
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("MyApp"), layout.getEventDataset());
		layout.setEventDataset(LOG4CXX_STR("MyApp.audit"));
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("MyApp.audit"), layout.getEventDataset());
		layout.setEventDataset(LogString());
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("MyApp"), layout.getEventDataset());
	}

	/**
	 * Tests \@timestamp is an ISO 8601 UTC time with millisecond precision.
	 */
	void testTimestamp()
	{
		ECSLayout layout;
		layout.activateOptions();
		for (int i = 0; i < 3; ++i)
		{
			auto event = makeEvent(LOG4CXX_STR("Hello"));
			LogString output;
			layout.format(output, event);
			auto expected = LOG4CXX_STR("{\"@timestamp\":\"") + expectedTimestamp(event) + LOG4CXX_STR("\",");
			LOGUNIT_ASSERT_EQUAL(expected, output.substr(0, expected.size()));
		}
	}

	/**
	 * Tests the output when no option is set.
	 */
	void testFormat()
	{
		ECSLayout layout;
		layout.activateOptions();
		auto event = makeEvent(LOG4CXX_STR("Hello \"world\"\n"));
		LogString output;
		layout.format(output, event);
		LogString expected = leadingFields(event, LOG4CXX_STR("Hello \\\"world\\\"\\n"))
			+ commonFields(event)
			+ LOG4CXX_STR("}") + LOG4CXX_EOL;
		LOGUNIT_ASSERT_EQUAL(expected, output);
	}

	void testFormatWithServiceFields()
	{
		ECSLayout layout;
		layout.setServiceName(LOG4CXX_STR("MyApp"));
		layout.setServiceVersion(LOG4CXX_STR("1.2.3"));
		layout.setServiceEnvironment(LOG4CXX_STR("production"));
		layout.setServiceNodeName(LOG4CXX_STR("node-1"));
		layout.activateOptions();
		auto event = makeEvent(LOG4CXX_STR("Hello"));
		LogString output;
		layout.format(output, event);
		LogString expected = leadingFields(event, LOG4CXX_STR("Hello"))
			+ commonFields(event)
			+ LOG4CXX_STR(",\"service.name\":\"MyApp\"")
			+ LOG4CXX_STR(",\"service.version\":\"1.2.3\"")
			+ LOG4CXX_STR(",\"service.environment\":\"production\"")
			+ LOG4CXX_STR(",\"service.node.name\":\"node-1\"")
			+ LOG4CXX_STR(",\"event.dataset\":\"MyApp\"")
			+ LOG4CXX_STR("}") + LOG4CXX_EOL;
		LOGUNIT_ASSERT_EQUAL(expected, output);

		layout.setEventDataset(LOG4CXX_STR("MyApp.audit"));
		layout.setServiceVersion(LogString());
		output.clear();
		layout.format(output, event);
		expected = leadingFields(event, LOG4CXX_STR("Hello"))
			+ commonFields(event)
			+ LOG4CXX_STR(",\"service.name\":\"MyApp\"")
			+ LOG4CXX_STR(",\"service.environment\":\"production\"")
			+ LOG4CXX_STR(",\"service.node.name\":\"node-1\"")
			+ LOG4CXX_STR(",\"event.dataset\":\"MyApp.audit\"")
			+ LOG4CXX_STR("}") + LOG4CXX_EOL;
		LOGUNIT_ASSERT_EQUAL(expected, output);
	}

	/**
	 * Tests the NDC is output as tags and MDC entries as top level fields,
	 * except MDC entries that would duplicate a field name.
	 */
	void testFormatWithContext()
	{
		ECSLayout layout;
		layout.setServiceName(LOG4CXX_STR("MyApp"));
		layout.activateOptions();
		NDC::push(LOG4CXX_STR("one"));
		NDC::push(LOG4CXX_STR("two"));
		MDC::put(LOG4CXX_STR("trace.id"), LOG4CXX_STR("4bf92f3577b34da6"));
		MDC::put(LOG4CXX_STR("user.name"), LOG4CXX_STR("a \"quoted\" name"));
		MDC::put(LOG4CXX_STR("message"), LOG4CXX_STR("ignored"));
		MDC::put(LOG4CXX_STR("service.name"), LOG4CXX_STR("ignored"));
		MDC::put(LOG4CXX_STR("tags"), LOG4CXX_STR("ignored"));
		MDC::put(LOG4CXX_STR("service.version"), LOG4CXX_STR("2.0"));
		MDC::put(LOG4CXX_STR("log.origin.function"), LOG4CXX_STR("main"));
		auto event = makeEvent(LOG4CXX_STR("Hello"));
		LogString output;
		layout.format(output, event);
		LogString expected = leadingFields(event, LOG4CXX_STR("Hello"))
			+ commonFields(event)
			+ LOG4CXX_STR(",\"service.name\":\"MyApp\"")
			+ LOG4CXX_STR(",\"event.dataset\":\"MyApp\"")
			+ LOG4CXX_STR(",\"tags\":[\"one two\"]")
			+ LOG4CXX_STR(",\"log.origin.function\":\"main\"")
			+ LOG4CXX_STR(",\"service.version\":\"2.0\"")
			+ LOG4CXX_STR(",\"trace.id\":\"4bf92f3577b34da6\"")
			+ LOG4CXX_STR(",\"user.name\":\"a \\\"quoted\\\" name\"")
			+ LOG4CXX_STR("}") + LOG4CXX_EOL;
		LOGUNIT_ASSERT_EQUAL(expected, output);
	}

	void testFormatWithLocationInfo()
	{
		ECSLayout layout;
		layout.setLocationInfo(true);
		layout.activateOptions();
		MDC::put(LOG4CXX_STR("log.origin.function"), LOG4CXX_STR("ignored"));
		auto event = makeEvent(LOG4CXX_STR("Hello"),
			LocationInfo("/src/com/foo/bar.cpp", "bar.cpp", "void com::foo::Bar::doIt(int)", 42));
		LogString output;
		layout.format(output, event);
		LogString expected = leadingFields(event, LOG4CXX_STR("Hello"))
			+ commonFields(event)
			+ LOG4CXX_STR(",\"log.origin.file.name\":\"bar.cpp\"")
			+ LOG4CXX_STR(",\"log.origin.file.line\":42")
			+ LOG4CXX_STR(",\"log.origin.function\":\"com::foo::Bar::doIt\"")
			+ LOG4CXX_STR("}") + LOG4CXX_EOL;
		LOGUNIT_ASSERT_EQUAL(expected, output);

		event = makeEvent(LOG4CXX_STR("Hello"),
			LocationInfo("/src/main.cpp", "main.cpp", "int main(int, char**)", 7));
		output.clear();
		layout.format(output, event);
		expected = leadingFields(event, LOG4CXX_STR("Hello"))
			+ commonFields(event)
			+ LOG4CXX_STR(",\"log.origin.file.name\":\"main.cpp\"")
			+ LOG4CXX_STR(",\"log.origin.file.line\":7")
			+ LOG4CXX_STR(",\"log.origin.function\":\"main\"")
			+ LOG4CXX_STR("}") + LOG4CXX_EOL;
		LOGUNIT_ASSERT_EQUAL(expected, output);
	}

	/**
	 * Tests no log.origin fields are output when the location is unknown.
	 */
	void testFormatWithoutAvailableLocationInfo()
	{
		ECSLayout layout;
		layout.setLocationInfo(true);
		layout.activateOptions();
		auto event = makeEvent(LOG4CXX_STR("Hello"));
		LogString output;
		layout.format(output, event);
		LogString expected = leadingFields(event, LOG4CXX_STR("Hello"))
			+ commonFields(event)
			+ LOG4CXX_STR("}") + LOG4CXX_EOL;
		LOGUNIT_ASSERT_EQUAL(expected, output);
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(ECSLayoutTest);
