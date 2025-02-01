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
#include <log4cxx/logstring.h>
#include <log4cxx/ndc.h>
#include <log4cxx/helpers/stringhelper.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/mdc.h>
#include <log4cxx/htmllayout.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Setup HTMLLayout
	HTMLLayout layout;
	Pool p;

	FuzzedDataProvider fdp(data, size);

	// Optional locationinfo
	if (fdp.ConsumeBool()) {
		layout.setOption(LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("true"));
	}
	// Optional threadinfo
	if (fdp.ConsumeBool()) {
		LOG4CXX_DECODE_CHAR(title, fdp.ConsumeRandomLengthString());
		layout.setOption(LOG4CXX_STR("TITLE"), title);
	}

	// Header
	if (fdp.ConsumeBool()) {
		std::string headerStr = fdp.ConsumeRandomLengthString();
		LogString header;
		Transcoder::decode(headerStr, header);
		layout.appendHeader(header, p);
	}

	// Create random strings we need later
	std::string key1Str = fdp.ConsumeRandomLengthString();
	std::string val1Str = fdp.ConsumeRandomLengthString();
	std::string key2Str = fdp.ConsumeRandomLengthString();
	std::string val2Str = fdp.ConsumeRandomLengthString();
	std::string key3 = fdp.ConsumeRandomLengthString();
	std::string val3 = fdp.ConsumeRandomLengthString();
	std::string key4 = fdp.ConsumeRandomLengthString();
	std::string val4 = fdp.ConsumeRandomLengthString();
	std::string ndcMessage = fdp.ConsumeRandomLengthString();
	std::string loggerStr = fdp.ConsumeRandomLengthString();
	std::string contentStr = fdp.ConsumeRemainingBytesAsString();

	LogString key1, key2, val1, val2, logger, content;

	Transcoder::decode(loggerStr, logger);
	Transcoder::decode(key1Str, key1);
	Transcoder::decode(val1Str, val2);
	Transcoder::decode(key2Str, key2);
	Transcoder::decode(val2Str, val2);
	Transcoder::decode(contentStr, content);
	
	LevelPtr level = log4cxx::Level::getInfo();
	NDC::push(ndcMessage);
	spi::LoggingEventPtr event = log4cxx::spi::LoggingEventPtr(
		new log4cxx::spi::LoggingEvent(
			logger, level, content, LOG4CXX_LOCATION));

	// Set properties
	event->setProperty(key1, val1);
	event->setProperty(key2, val2);

	// Set MDC
	log4cxx::MDC::put(key3, val3);
	log4cxx::MDC::put(key4, val4);

	// Call the target API
	log4cxx::LogString result;
	layout.format(result, event, p);

	// Clean up
	log4cxx::NDC::clear();
	log4cxx::MDC::clear();
  	return 0;
}
