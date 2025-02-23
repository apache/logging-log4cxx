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

#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/transcoder.h>

#include <log4cxx/pattern/patternconverter.h>
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
	const int MaximumOptionByteCount = 1000;
	const int MaximumNameByteCount = 100;
}

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::pattern;

// Creates options from the FuzzedDataProvider
auto createOptions(FuzzedDataProvider* fdp) {
	auto opt1Str = fdp->ConsumeRandomLengthString(MaximumOptionByteCount);
	auto opt2Str = fdp->ConsumeRandomLengthString(MaximumOptionByteCount);
	auto opt3Str = fdp->ConsumeRandomLengthString(MaximumOptionByteCount);
	auto opt4Str = fdp->ConsumeRandomLengthString(MaximumOptionByteCount);
	auto opt5Str = fdp->ConsumeRandomLengthString(MaximumOptionByteCount);

	LogString opt1, opt2, opt3, opt4, opt5;

	Transcoder::decode(opt1Str, opt1);
	Transcoder::decode(opt2Str, opt2);
	Transcoder::decode(opt3Str, opt3);
	Transcoder::decode(opt4Str, opt4);
	Transcoder::decode(opt5Str, opt5);

	return std::vector<log4cxx::LogString>
		{ opt1
		, opt2
		, opt3
		, opt4
		, opt5
		};
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Create a FuzzedDataProvider which we will use to
	// create strings from "data".
	FuzzedDataProvider fdp(data, size);

	auto loggerStr = fdp.ConsumeRandomLengthString();
	auto contentStr = fdp.ConsumeRandomLengthString();

	LogString logger, content;
	Transcoder::decode(loggerStr, logger);
	Transcoder::decode(contentStr, content);

	// Create the event
	auto level = Level::getInfo();

	Pool p;

	auto event = std::make_shared<LoggingEvent>(
			logger, level, content, LOG4CXX_LOCATION);
	// Select a converter and invoke it.
	switch(fdp.ConsumeIntegralInRange<int>(0, 14)) {
		case 0: {
			auto nameStr = fdp.ConsumeRandomLengthString(MaximumNameByteCount);
			auto opionStr = fdp.ConsumeRandomLengthString(MaximumOptionByteCount);
			LogString name, option;
			Transcoder::decode(nameStr, name);
			Transcoder::decode(opionStr, option);

			PropertiesPatternConverter(name, option).format(event, logger, p);
			break;
		}
		case 1: {
			LoggerPatternConverter(createOptions(&fdp)).format(event, logger, p);
			break;
		}
		case 2: {
			ClassNamePatternConverter(createOptions(&fdp)).format(event, logger, p);
			break;
		}
		case 3: {
			DatePatternConverter(createOptions(&fdp)).format(event, logger, p);
			break;
		}
		case 4: {
			FullLocationPatternConverter().format(event, logger, p);
			break;
		}
		case 5: {
			LineLocationPatternConverter().format(event, logger, p);
			break;
		}
		case 6: {
			MessagePatternConverter().format(event, logger, p);
			break;
		}
		case 7: {
			LineSeparatorPatternConverter().format(event, logger, p);
			break;
		}
		case 8: {
			MethodLocationPatternConverter().format(event, logger, p);
			break;
		}
		case 9: {
			LevelPatternConverter().format(event, logger, p);
		}
		case 10: {
			RelativeTimePatternConverter().format(event, logger, p);
			break;
		}
		case 11: {
			ThreadPatternConverter().format(event, logger, p);
			break;
		}
		case 12: {
			ThreadUsernamePatternConverter().format(event, logger, p);
			break;
		}
		case 13: {
			NDCPatternConverter().format(event, logger, p);
			break;
		}
		case 14: {
			ThrowableInformationPatternConverter(fdp.ConsumeBool()).format(event, logger, p);
			break;
		}
	}
	return 0;
}
