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
#include <iostream>
#include <string>
#include <cwchar>
#include <log4cxx/logstring.h>
#include <log4cxx/ndc.h>
#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/helpers/stringhelper.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/mdc.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Setup XMLLayout
	log4cxx::xml::XMLLayout layout;
	Pool p;

	// Create random strings
	FuzzedDataProvider fdp(data, size);
	std::string key1 = fdp.ConsumeRandomLengthString();
	std::string val1 = fdp.ConsumeRandomLengthString();
	std::string key2 = fdp.ConsumeRandomLengthString();
	std::string val2 = fdp.ConsumeRandomLengthString();
	std::string ndcMessage = fdp.ConsumeRandomLengthString();
	std::string loggerString = fdp.ConsumeRandomLengthString();
	std::string propkey = fdp.ConsumeRandomLengthString();
	std::string propval = fdp.ConsumeRandomLengthString();
	std::string content = fdp.ConsumeRemainingBytesAsString();

	log4cxx::LevelPtr level = log4cxx::Level::getInfo();
	log4cxx::NDC::push(ndcMessage);
        LogString logstring1;
        LogString key1LogString;
        LogString val1LogString;
        LogString propkeyLogString;
        LogString propvalLogString;
        LogString logger;

        Transcoder::decode(content, logstring1);
        Transcoder::decode(loggerString, logger);
        Transcoder::decode(key1, key1LogString);
        Transcoder::decode(val1, val1LogString);
        Transcoder::decode(propkey, propkeyLogString);
        Transcoder::decode(propval, propvalLogString);
	log4cxx::spi::LoggingEventPtr event = log4cxx::spi::LoggingEventPtr(
		new log4cxx::spi::LoggingEvent(
			logger, level, logstring1, LOG4CXX_LOCATION));
	// Set properties
	layout.setProperties(true);
	event->setProperty(propkeyLogString, propvalLogString);


	// Set MDC
	log4cxx::MDC::put(key2, val2);

	// Location info
	layout.setLocationInfo(true);

	// Call the target API
	log4cxx::LogString result;
	layout.format(result, event, p);

	// Clean up
	log4cxx::NDC::clear();
	log4cxx::MDC::clear();
  	return 0;
}
