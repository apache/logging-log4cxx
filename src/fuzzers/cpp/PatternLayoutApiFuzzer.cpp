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

//
// Fuzzer for PatternLayout as a whole component: the real conversion-rule
// map (including %Y ColorStart, %y ColorEnd and %J MDC, which the existing
// PatternParserFuzzer/PatternConverterFuzzer subset maps do not contain),
// the layout option matrix (ConversionPattern plus the six per-level color
// options), and the formatting of events that carry MDC, NDC, event
// properties, location info and a fuzzed level.
//
// ColorStartPatternConverter, ColorEndPatternConverter,
// MDCPatternConverter and IntegerPatternConverter have had no coverage at
// all; the fuzzed pattern plus option matrix also drives the residual dark
// regions of patternlayout.cpp, patternparser.cpp and messagebuffer.cpp
// (option parsing, %-escape edge cases, abbreviation and formatting-buffer
// growth).
//
// Expected defect classes: memory safety in converter option handling and
// pattern parsing, message-buffer growth on adversarial patterns, and
// level/color lookup errors.
//

#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/mdc.h>
#include <log4cxx/ndc.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

namespace
{
	const int MaximumPatternByteCount = 4096;
	const int MaximumMessageByteCount = 2048;
	const int MaximumColorByteCount = 64;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	FuzzedDataProvider fdp(data, size);

	PatternLayoutPtr layout(new PatternLayout());

	// Option matrix: pattern plus the per-level color options consumed by
	// ColorStartPatternConverter.
	std::string patternStr = fdp.ConsumeRandomLengthString(MaximumPatternByteCount);
	LogString pattern;
	Transcoder::decode(patternStr, pattern);
	layout->setOption(LOG4CXX_STR("CONVERSIONPATTERN"), pattern);

	LogString traceColor, debugColor, infoColor, warnColor, errorColor, fatalColor;
	Transcoder::decode(fdp.ConsumeRandomLengthString(MaximumColorByteCount), traceColor);
	Transcoder::decode(fdp.ConsumeRandomLengthString(MaximumColorByteCount), debugColor);
	Transcoder::decode(fdp.ConsumeRandomLengthString(MaximumColorByteCount), infoColor);
	Transcoder::decode(fdp.ConsumeRandomLengthString(MaximumColorByteCount), warnColor);
	Transcoder::decode(fdp.ConsumeRandomLengthString(MaximumColorByteCount), errorColor);
	Transcoder::decode(fdp.ConsumeRandomLengthString(MaximumColorByteCount), fatalColor);
	layout->setOption(LOG4CXX_STR("TRACECOLOR"), traceColor);
	layout->setOption(LOG4CXX_STR("DEBUGCOLOR"), debugColor);
	layout->setOption(LOG4CXX_STR("INFOCOLOR"), infoColor);
	layout->setOption(LOG4CXX_STR("WARNCOLOR"), warnColor);
	layout->setOption(LOG4CXX_STR("ERRORCOLOR"), errorColor);
	layout->setOption(LOG4CXX_STR("FATALCOLOR"), fatalColor);

	layout->activateOptions();

	// Event with MDC, NDC, properties, location info and a fuzzed level.
	std::string keyStr = fdp.ConsumeRandomLengthString(64);
	std::string valStr = fdp.ConsumeRandomLengthString(256);
	std::string msgStr = fdp.ConsumeRemainingBytesAsString();

	LogString key, value, message;
	Transcoder::decode(keyStr, key);
	Transcoder::decode(valStr, value);
	Transcoder::decode(msgStr, message);

	spi::LoggingEventPtr event(new spi::LoggingEvent(
		LOG4CXX_STR("fuzz.pattern.logger"),
		Level::toLevelLS(key, Level::getInfo()),
		message,
		LOG4CXX_LOCATION));
	event->setProperty(key, value);

	MDC::put(key, value);
	NDC::push(value);

	LogString output;
	layout->format(output, event);

	NDC::clear();
	MDC::remove(key);
	return 0;
}
