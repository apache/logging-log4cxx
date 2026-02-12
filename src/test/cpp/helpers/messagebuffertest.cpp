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

#include <log4cxx/helpers/messagebuffer.h>
#include <iomanip>
#include "../insertwide.h"
#include "../logunit.h"
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include "util/compare.h"
#include <cassert>

#if LOG4CXX_CFSTRING_API
	#include <CoreFoundation/CFString.h>
#endif

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
 *  Test MessageBuffer.
 */
LOGUNIT_CLASS(MessageBufferTest)
{
	LOGUNIT_TEST_SUITE(MessageBufferTest);
	LOGUNIT_TEST(testInsertChar);
	LOGUNIT_TEST(testInsertConstStr);
	LOGUNIT_TEST(testInsertStr);
	LOGUNIT_TEST(testInsertString);
	LOGUNIT_TEST(testInsertNull);
	LOGUNIT_TEST(testInsertInt);
	LOGUNIT_TEST(testInsertManipulator);
	LOGUNIT_TEST(testBaseChange);
#if LOG4CXX_WCHAR_T_API
	LOGUNIT_TEST(testInsertConstWStr);
	LOGUNIT_TEST(testInsertWString);
	LOGUNIT_TEST(testInsertWStr);
#endif
#if LOG4CXX_UNICHAR_API
	LOGUNIT_TEST(testInsertConstUStr);
	LOGUNIT_TEST(testInsertUString);
#endif
#if LOG4CXX_CFSTRING_API
	LOGUNIT_TEST(testInsertCFString);
#endif
	LOGUNIT_TEST(testInsertCalculatedValue);
	LOGUNIT_TEST_SUITE_END();


#ifdef _DEBUG
	struct Fixture
	{
		Fixture() {
			helpers::LogLog::setInternalDebugging(true);
		}
	} suiteFixture;
#endif

public:
	void testInsertChar()
	{
		MessageBuffer buf;
		std::string greeting("Hello, World");
		CharMessageBuffer& retval = buf << "Hello, Worl" << 'd';
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertConstStr()
	{
		MessageBuffer buf;
		std::string greeting("Hello, World");
		CharMessageBuffer& retval = buf << "Hello" << ", World";
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertStr()
	{
		MessageBuffer buf;
		std::string greeting("Hello, World");
		char* part1 = (char*) malloc(10 * sizeof(wchar_t));
		strcpy(part1, "Hello");
		char* part2 = (char*) malloc(10 * sizeof(wchar_t));
		strcpy(part2, ", World");
		CharMessageBuffer& retval = buf << part1 << part2;
		free(part1);
		free(part2);
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertString()
	{
		MessageBuffer buf;
		std::string greeting("Hello, World");
		CharMessageBuffer& retval = buf << std::string("Hello") << std::string(", World");
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertNull()
	{
		MessageBuffer buf;
		std::string greeting("Hello, null");
		CharMessageBuffer& retval = buf << "Hello, " << (const char*) 0;
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertInt()
	{
		MessageBuffer buf;
		std::string greeting("Hello, 5");
		std::ostream& retval = buf << "Hello, " << 5;
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(true, buf.hasStream());
	}

	void testInsertManipulator()
	{
		MessageBuffer buf;
		std::string greeting("pi=3.142");
		std::ostream& retval = buf << "pi=" << std::setprecision(4) << 3.1415926;
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(true, buf.hasStream());
	}

	void testBaseChange()
	{
		LoggerPtr root;
		LoggerPtr logger;

		root = Logger::getRootLogger();
		logger = Logger::getLogger(LOG4CXX_STR("java.org.apache.log4j.PatternLayoutTest"));

		auto status = PropertyConfigurator::configure(LOG4CXX_FILE("input/messagebuffer1.properties"));
		LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);

		int num = 220;
		LOG4CXX_INFO(logger, "number in hex: " << std::hex << num);
		LOG4CXX_INFO(logger, "number in dec: " << num);

		LOGUNIT_ASSERT(Compare::compare(LOG4CXX_STR("output/messagebuffer"), LOG4CXX_FILE("witness/messagebuffer.1")));

		auto rep = root->getLoggerRepository();

		if (rep)
		{
			rep->resetConfiguration();
		}
	}

#if LOG4CXX_WCHAR_T_API
	void testInsertConstWStr()
	{
		MessageBuffer buf;
		std::wstring greeting(L"Hello, World");
		WideMessageBuffer& retval = buf << L"Hello" << L", World";
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertWString()
	{
		MessageBuffer buf;
		std::wstring greeting(L"Hello, World");
		WideMessageBuffer& retval = buf << std::wstring(L"Hello") << std::wstring(L", World");
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertWStr()
	{
		MessageBuffer buf;
		std::wstring greeting(L"Hello, World");
		wchar_t* part1 = (wchar_t*) malloc(10 * sizeof(wchar_t));
		wcscpy(part1, L"Hello");
		wchar_t* part2 = (wchar_t*) malloc(10 * sizeof(wchar_t));
		wcscpy(part2, L", World");
		WideMessageBuffer& retval = buf << part1 << part2;
		free(part1);
		free(part2);
		LOGUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}
#endif

#if LOG4CXX_UNICHAR_API
	void testInsertConstUStr()
	{
		MessageBuffer buf;
		const log4cxx::UniChar hello[] = { 'H', 'e', 'l', 'l', 'o', 0 };
		const log4cxx::UniChar world[] = { ',', ' ', 'W', 'o', 'r', 'l', 'd', 0 };
		const log4cxx::UniChar greeting[] = { 'H', 'e', 'l', 'l', 'o',
				',', ' ', 'W', 'o', 'r', 'l', 'd', 0
			};
		UniCharMessageBuffer& retval = buf << hello << world;
		LOGUNIT_ASSERT_EQUAL(std::basic_string<log4cxx::UniChar>(greeting), buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

	void testInsertUString()
	{
		MessageBuffer buf;
		const log4cxx::UniChar hello[] = { 'H', 'e', 'l', 'l', 'o', 0 };
		const log4cxx::UniChar world[] = { ',', ' ', 'W', 'o', 'r', 'l', 'd', 0 };
		const log4cxx::UniChar greeting[] = { 'H', 'e', 'l', 'l', 'o',
				',', ' ', 'W', 'o', 'r', 'l', 'd', 0
			};
		UniCharMessageBuffer& retval = buf << std::basic_string<log4cxx::UniChar>(hello)
			<< std::basic_string<log4cxx::UniChar>(world);
		LOGUNIT_ASSERT_EQUAL(std::basic_string<log4cxx::UniChar>(greeting), buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}

#endif

#if LOG4CXX_UNICHAR_API && LOG4CXX_CFSTRING_API
	void testInsertCFString()
	{
		MessageBuffer buf;
		const log4cxx::UniChar greeting[] = { 'H', 'e', 'l', 'l', 'o',
				',', ' ', 'W', 'o', 'r', 'l', 'd', 0
			};
		UniCharMessageBuffer& retval = buf << CFSTR("Hello")
			<< CFSTR(", World");
		LOGUNIT_ASSERT_EQUAL(std::basic_string<log4cxx::UniChar>(greeting), buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}
#elif LOG4CXX_CFSTRING_API
	void testInsertCFString()
	{
		MessageBuffer buf;
		const log4cxx::logchar greeting[] = { 'H', 'e', 'l', 'l', 'o',
				',', ' ', 'W', 'o', 'r', 'l', 'd', 0
			};
		CharMessageBuffer& retval = buf << CFSTR("Hello")
			<< CFSTR(", World");
		LOGUNIT_ASSERT_EQUAL(std::basic_string<log4cxx::logchar>(greeting), buf.str(retval));
		LOGUNIT_ASSERT_EQUAL(false, buf.hasStream());
	}
#endif

	// Use the Gregory-Leibniz series to approximate π
	static double calculatePi(int terms, int level, int initialTerm = 0)
	{
		double pi = 0.0;
		if (0 < level)
		{
			MessageBuffer buf;
			auto& retval = buf << LOG4CXX_STR("level ") << level << " pi " << std::setprecision(6) << (pi = calculatePi(terms * 2, level - 1, terms));
			assert(buf.hasStream());
			auto msg = buf.str(retval);
			LOG4CXX_DECODE_CHAR(lsMsg, msg);
			helpers::LogLog::debug(lsMsg);
			pi /= 4; // Divide by 4 to get the value of the previous level
		}
		for (int i = initialTerm; i < terms; i++)
		{
			if (i % 2 == 0)
			{
				pi += 1.0 / (2 * i + 1); // Add for even index
			}
			else
			{
				pi -= 1.0 / (2 * i + 1); // Subtract for odd index
			}
			if ((i + 1) % 500 == 0)
			{
				MessageBuffer buf;
				auto& retval = buf << LOG4CXX_STR("level ") << level << " term " << i << " pi " << std::setprecision(6) << (pi * 4);
				assert(buf.hasStream());
				auto msg = buf.str(retval);
				LOG4CXX_DECODE_CHAR(lsMsg, msg);
				helpers::LogLog::debug(lsMsg);
			}
		}
		return pi * 4; // Multiply by 4 to get Pi
	}

	// Checks what happens with 4 concurrently active MessageBuffer objects in the same thread, each using using a std::stringstream.
	// The Log4cxx debug output shows the partially completed message (at the 3rd level) being reset for use by the 4th level MessageBuffer.
	void testInsertCalculatedValue()
	{
		MessageBuffer buf;
		std::string expectedValue("pi=3.142 calculated pi=3.141 using 4000 terms");
		auto& retval = buf << "pi=" << std::setprecision(4) << 3.14159265358979323846 << " calculated pi=" << std::setprecision(4) << calculatePi(1000, 2) << " using 4000 terms";
		LOGUNIT_ASSERT_EQUAL(true, buf.hasStream());
		LOGUNIT_ASSERT_EQUAL(expectedValue, buf.str(retval));
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(MessageBufferTest);

