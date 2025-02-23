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

#include "stdint.h"
#include <log4cxx/nt/nteventlogappender.h>
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/stringhelper.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/pattern/patternparser.h>
#include <log4cxx/helpers/transcoder.h>

#include <log4cxx/pattern/loggerpatternconverter.h>
#include <log4cxx/pattern/literalpatternconverter.h>
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

namespace
{
    const int MaximumLoggerNameByteCount = 100;
    const int MaximumMessageByteCount = 10000;
    const int MaximumPatternByteCount = 10000;
}
using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::pattern;

#define RULES_PUT(spec, cls) \
	map.insert(PatternMap::value_type(LOG4CXX_STR(spec), (PatternConstructor) cls ::newInstance))

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Create a FuzzedDataProvider which we
	// will use to create strings from "data".
	FuzzedDataProvider fdp(data, size);
	
	std::string loggerStr = fdp.ConsumeRandomLengthString(MaximumLoggerNameByteCount);
	std::string content = fdp.ConsumeRandomLengthString(MaximumMessageByteCount);
	std::string pattern = fdp.ConsumeRandomLengthString(MaximumPatternByteCount);

	LogString contentLogString;
	LogString loggerLogString;
	LogString patternLogString;

	Transcoder::decode(content, contentLogString);
	Transcoder::decode(loggerStr, loggerLogString);
	Transcoder::decode(pattern, patternLogString);

	// Create the event
	log4cxx::LogString logger = loggerLogString;
	log4cxx::LevelPtr level = log4cxx::Level::getInfo();
	log4cxx::spi::LoggingEventPtr event = log4cxx::spi::LoggingEventPtr(
		new log4cxx::spi::LoggingEvent(
			logger, level, contentLogString, LOG4CXX_LOCATION));


	log4cxx::helpers::Pool p;
	PatternMap patternMap = getFormatSpecifiers();
	std::vector<PatternConverterPtr> converters;
	std::vector<FormattingInfoPtr> fields;

	PatternParser::parse(patternLogString, converters, fields, patternMap);

  	return 0;
}
