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
#include <log4cxx/pattern/patternconverter.h>
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

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::pattern;

#if LOG4CXX_WCHAR_T_API || LOG4CXX_LOGCHAR_IS_WCHAR_T
wchar_t* wencode(const std::string& src, Pool& p)
{
        wchar_t* dst = (wchar_t*) p.palloc((src.length() + 1) * sizeof(wchar_t));
        dst[src.length()] = 0;
        std::memcpy(dst, src.data(), src.length() * sizeof(wchar_t));
        return dst;
}
#endif

// Creates options from the FuzzedDataProvider
std::vector<log4cxx::LogString> createOptions(FuzzedDataProvider* fdp) {
	std::string opt1Str = fdp->ConsumeRandomLengthString();
	std::string opt2Str = fdp->ConsumeRandomLengthString();
	std::string opt3Str = fdp->ConsumeRandomLengthString();
	std::string opt4Str = fdp->ConsumeRandomLengthString();
	std::string opt5Str = fdp->ConsumeRandomLengthString();
	
	LogString opt1, opt2, opt3, opt4, opt5;

	Transcoder::decode(opt1Str, opt1);
	Transcoder::decode(opt2Str, opt2);
	Transcoder::decode(opt3Str, opt3);
	Transcoder::decode(opt4Str, opt4);
	Transcoder::decode(opt5Str, opt5);

	std::vector<log4cxx::LogString> options =
        { opt1
        , opt2
        , opt3
        , opt4
        , opt5
        };
       return options;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Create a FuzzedDataProvider which we will use to
	// create strings from "data".
	FuzzedDataProvider fdp(data, size);
	
	std::string loggerStr = fdp.ConsumeRandomLengthString();
	std::string contentStr = fdp.ConsumeRandomLengthString();
	
	LogString logger, content;
	Transcoder::decode(loggerStr, logger);
	Transcoder::decode(contentStr, content);

	// Create the event
	LevelPtr level = Level::getInfo();

	Pool p;

	log4cxx::spi::LoggingEventPtr event = log4cxx::spi::LoggingEventPtr(
		new log4cxx::spi::LoggingEvent(
			logger, level, content, LOG4CXX_LOCATION));
	// Select a converter and invoke it.
	switch(fdp.ConsumeIntegralInRange<int>(0, 14)) {
		case 0: {
			std::string str1 = fdp.ConsumeRandomLengthString();
			std::string str2 = fdp.ConsumeRandomLengthString();
			LogString a1, a2;
			Transcoder::decode(str1, a1);
			Transcoder::decode(str2, a2);

			PropertiesPatternConverter* converter = new PropertiesPatternConverter(a1, a2);
			converter->format(event, logger, p);
			delete converter;
		}
		case 1: {
			std::vector<log4cxx::LogString> options = createOptions(&fdp);
			LoggerPatternConverter* converter = new LoggerPatternConverter(options);
			converter->format(event, logger, p);
			delete converter;
		}
		case 2: {
			std::vector<log4cxx::LogString> options = createOptions(&fdp);
			ClassNamePatternConverter* converter = new ClassNamePatternConverter(options);
			converter->format(event, logger, p);
			delete converter;
		}
		case 3: {
			std::vector<log4cxx::LogString> options = createOptions(&fdp);
			DatePatternConverter* converter = new DatePatternConverter(options);
			converter->format(event, logger, p);
			delete converter;
		}
		case 4: {
			FullLocationPatternConverter* converter = new FullLocationPatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 5: {
			LineLocationPatternConverter* converter = new LineLocationPatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 6: {
			MessagePatternConverter* converter = new MessagePatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 7: {
			LineSeparatorPatternConverter* converter = new LineSeparatorPatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 8: {
			MethodLocationPatternConverter* converter = new MethodLocationPatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 9: {
			LevelPatternConverter* converter = new LevelPatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 10: {
			RelativeTimePatternConverter* converter = new RelativeTimePatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 11: {
			ThreadPatternConverter* converter = new ThreadPatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 12: {
			ThreadUsernamePatternConverter* converter = new ThreadUsernamePatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 13: {
			NDCPatternConverter* converter = new NDCPatternConverter();
			converter->format(event, logger, p);
			delete converter;
		}
		case 14: {
			ThrowableInformationPatternConverter* converter = new ThrowableInformationPatternConverter(fdp.ConsumeBool());
			converter->format(event, logger, p);
			delete converter;
		}
	}
  	return 0;
}
