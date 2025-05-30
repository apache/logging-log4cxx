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

#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/level.h>

#include "num343patternconverter.h"
#include "../testchar.h"
#include "../insertwide.h"
#include "../logunit.h"
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/pattern/patternparser.h>
#include <log4cxx/pattern/patternconverter.h>
#include <log4cxx/helpers/relativetimedateformat.h>
#include <log4cxx/helpers/simpledateformat.h>
#include <log4cxx/helpers/transcoder.h>


#include <log4cxx/pattern/loggerpatternconverter.h>
#include <log4cxx/pattern/literalpatternconverter.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/pattern/classnamepatternconverter.h>
#include <log4cxx/pattern/datepatternconverter.h>
#include <log4cxx/pattern/filedatepatternconverter.h>
#include <log4cxx/pattern/filelocationpatternconverter.h>
#include <log4cxx/pattern/fulllocationpatternconverter.h>
#include <log4cxx/pattern/integerpatternconverter.h>
#include <log4cxx/pattern/linelocationpatternconverter.h>
#include <log4cxx/pattern/messagepatternconverter.h>
#include <log4cxx/pattern/lineseparatorpatternconverter.h>
#include <log4cxx/pattern/methodlocationpatternconverter.h>
#include <log4cxx/pattern/levelpatternconverter.h>
#include <log4cxx/pattern/relativetimepatternconverter.h>
#include <log4cxx/pattern/threadpatternconverter.h>
#include <log4cxx/pattern/ndcpatternconverter.h>
#include <log4cxx/pattern/propertiespatternconverter.h>
#include <log4cxx/pattern/throwableinformationpatternconverter.h>
#include <log4cxx/pattern/threadusernamepatternconverter.h>

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::pattern;

#define RULES_PUT(spec, cls) \
	map.insert(PatternMap::value_type(LOG4CXX_STR(spec), (PatternConstructor) cls ::newInstance))


LOGUNIT_CLASS(PatternParserTestCase)
{
	LOGUNIT_TEST_SUITE(PatternParserTestCase);
	LOGUNIT_TEST(testNewWord);
	LOGUNIT_TEST(testNewWord2);
	LOGUNIT_TEST(testBogusWord1);
	LOGUNIT_TEST(testBogusWord2);
	LOGUNIT_TEST(testBasic1);
	LOGUNIT_TEST(testBasic2);
	LOGUNIT_TEST(testMultiOption);
	LOGUNIT_TEST(testThreadUsername);
	LOGUNIT_TEST(testInvalidPatterns);
	LOGUNIT_TEST_SUITE_END();

	LoggingEventPtr event;

public:
	void setUp()
	{
		LogString threadName = LOG4CXX_STR("log4cxx-thr");

#if LOG4CXX_HAS_PTHREAD_SETNAME && !(defined(_WIN32) && defined(_LIBCPP_VERSION))
	LOG4CXX_ENCODE_CHAR(sthreadName, threadName);
	if( pthread_setname_np( pthread_self(), sthreadName.c_str() ) < 0 ){
		LOGLOG_ERROR( LOG4CXX_STR("unable to set thread name") );
	}
#elif defined(_WIN32)
	LOG4CXX_ENCODE_WCHAR(wthreadName, threadName);
	HRESULT hr = SetThreadDescription(GetCurrentThread(), wthreadName.c_str());
	if(FAILED(hr)){
		LOGLOG_ERROR( LOG4CXX_STR("unable to set thread name") );
	}
#else
		threadName = LOG4CXX_STR("(noname)");
#endif

		event = LoggingEventPtr(new LoggingEvent(
					LOG4CXX_STR("org.foobar"), Level::getInfo(), LOG4CXX_STR("msg 1"), LOG4CXX_LOCATION));
	}

	void tearDown()
	{
	}


	PatternMap getFormatSpecifiers()
	{
		PatternMap map;
		RULES_PUT("c", LoggerPatternConverter);
		RULES_PUT("logger", LoggerPatternConverter);

		RULES_PUT("C", ClassNamePatternConverter);
		RULES_PUT("class", ClassNamePatternConverter);

		RULES_PUT("d", DatePatternConverter);
		RULES_PUT("date", DatePatternConverter);

		RULES_PUT("F", FileLocationPatternConverter);
		RULES_PUT("file", FileLocationPatternConverter);

		RULES_PUT("l", FullLocationPatternConverter);

		RULES_PUT("L", LineLocationPatternConverter);
		RULES_PUT("line", LineLocationPatternConverter);

		RULES_PUT("m", MessagePatternConverter);
		RULES_PUT("message", MessagePatternConverter);

		RULES_PUT("n", LineSeparatorPatternConverter);

		RULES_PUT("M", MethodLocationPatternConverter);
		RULES_PUT("method", MethodLocationPatternConverter);

		RULES_PUT("p", LevelPatternConverter);
		RULES_PUT("level", LevelPatternConverter);

		RULES_PUT("r", RelativeTimePatternConverter);
		RULES_PUT("relative", RelativeTimePatternConverter);

		RULES_PUT("t", ThreadPatternConverter);
		RULES_PUT("thread", ThreadPatternConverter);

		RULES_PUT("T", ThreadUsernamePatternConverter);
		RULES_PUT("threadname", ThreadUsernamePatternConverter);

		RULES_PUT("x", NDCPatternConverter);
		RULES_PUT("ndc", NDCPatternConverter);

		RULES_PUT("X", PropertiesPatternConverter);
		RULES_PUT("properties", PropertiesPatternConverter);

		RULES_PUT("throwable", ThrowableInformationPatternConverter);

		return map;

	}

	void assertFormattedEquals(const LogString & pattern,
		const PatternMap & patternMap,
		const LogString & expected)
	{
		std::vector<PatternConverterPtr> converters;
		std::vector<FormattingInfoPtr> fields;
		PatternParser::parse(pattern, converters, fields, patternMap);
		Pool p;
		LogString actual;
		std::vector<FormattingInfoPtr>::const_iterator fieldIter = fields.begin();

		for (std::vector<PatternConverterPtr>::const_iterator converterIter = converters.begin();
			converterIter != converters.end();
			converterIter++, fieldIter++)
		{
			auto fieldStart = static_cast<int>(actual.length());
			(*converterIter)->format(event, actual, p);
			(*fieldIter)->format(fieldStart, actual);
		}

		LOGUNIT_ASSERT_EQUAL(expected, actual);
	}


	void testNewWord()
	{
		PatternMap testRules(getFormatSpecifiers());
		testRules.insert(
			PatternMap::value_type(LOG4CXX_STR("z343"),
				(PatternConstructor) Num343PatternConverter::newInstance));
		assertFormattedEquals(LOG4CXX_STR("%z343"), testRules, LOG4CXX_STR("343"));
	}


	/* Test whether words starting with the letter 'n' are treated differently,
	 * which was previously the case by mistake.
	 */
	void testNewWord2()
	{
		PatternMap testRules(getFormatSpecifiers());
		testRules.insert(
			PatternMap::value_type(LOG4CXX_STR("n343"),
				(PatternConstructor) Num343PatternConverter::newInstance));
		assertFormattedEquals(LOG4CXX_STR("%n343"), testRules, LOG4CXX_STR("343"));
	}

	void testBogusWord1()
	{
		assertFormattedEquals(LOG4CXX_STR("%, foobar"),
			getFormatSpecifiers(),
			LOG4CXX_STR("%, foobar"));
	}

	void testBogusWord2()
	{
		assertFormattedEquals(LOG4CXX_STR("xyz %, foobar"),
			getFormatSpecifiers(),
			LOG4CXX_STR("xyz %, foobar"));
	}

	void testBasic1()
	{
		assertFormattedEquals(LOG4CXX_STR("hello %-5level - %m%n"),
			getFormatSpecifiers(),
			LogString(LOG4CXX_STR("hello INFO  - msg 1")) + LOG4CXX_EOL);
	}

	void testBasic2()
	{
		Pool pool;
		RelativeTimeDateFormat relativeFormat;
		LogString expected;
		relativeFormat.format(expected, event->getTimeStamp(), pool);

		expected.append(LOG4CXX_STR(" INFO  ["));
		expected.append(event->getThreadName());
		expected.append(LOG4CXX_STR("] org.foobar - msg 1"));
		expected.append(LOG4CXX_EOL);

		assertFormattedEquals(LOG4CXX_STR("%relative %-5level [%thread] %logger - %m%n"),
			getFormatSpecifiers(),
			expected);
	}

	void testMultiOption()
	{
		Pool pool;

		SimpleDateFormat dateFormat(LOG4CXX_STR("HH:mm:ss"));
		LogString localTime;
		dateFormat.format(localTime, event->getTimeStamp(), pool);

		dateFormat.setTimeZone(TimeZone::getGMT());
		LogString utcTime;
		dateFormat.format(utcTime, event->getTimeStamp(), pool);

		LogString expected(utcTime);
		expected.append(1, LOG4CXX_STR(' '));
		expected.append(localTime);
		expected.append(LOG4CXX_STR(" org.foobar  - msg 1"));


		assertFormattedEquals(LOG4CXX_STR("%d{HH:mm:ss}{GMT} %d{HH:mm:ss} %c  - %m"),
			getFormatSpecifiers(),
			expected);
		// Check an invalid timezone is equivalent to an unspecified timezone
		assertFormattedEquals(LOG4CXX_STR("%d{HH:mm:ss}{GMT} %d{HH:mm:ss}{GMT-X} %c  - %m"),
			getFormatSpecifiers(),
			expected);
		assertFormattedEquals(LOG4CXX_STR("%d{HH:mm:ss}{GMT} %d{HH:mm:ss}{GMT-1:62222222} %c  - %m"),
			getFormatSpecifiers(),
			expected);
	}

	void testThreadUsername()
	{
		Pool pool;
		RelativeTimeDateFormat relativeFormat;
		LogString expected;
		relativeFormat.format(expected, event->getTimeStamp(), pool);

		expected.append(LOG4CXX_STR(" INFO  ["));
		expected.append(event->getThreadUserName());
		expected.append(LOG4CXX_STR("] org.foobar - msg 1"));
		expected.append(LOG4CXX_EOL);

		assertFormattedEquals(LOG4CXX_STR("%relative %-5level [%threadname] %logger - %m%n"),
			getFormatSpecifiers(),
			expected);
	}

	void testInvalidPatterns()
	{
		assertFormattedEquals(LOG4CXX_STR("%6666c"),
			getFormatSpecifiers(),
			LOG4CXX_STR("%6666c"));
		assertFormattedEquals(LOG4CXX_STR("%6.6666c"),
			getFormatSpecifiers(),
			LOG4CXX_STR("%6.6666c"));
	}

};

//
//   See bug LOGCXX-204
//
#if !defined(_MSC_VER) || _MSC_VER > 1200
	LOGUNIT_TEST_SUITE_REGISTRATION(PatternParserTestCase);
#endif
