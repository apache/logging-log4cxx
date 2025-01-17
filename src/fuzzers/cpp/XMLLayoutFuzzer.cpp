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
#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/helpers/stringhelper.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/mdc.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// Setup XMLLayout
	log4cxx::xml::XMLLayout layout;

	// Create random strings
	FuzzedDataProvider fdp(data, size);
	std::string key1 = fdp.ConsumeRandomLengthString();
	std::string val1 = fdp.ConsumeRandomLengthString();
	std::string key2 = fdp.ConsumeRandomLengthString();
	std::string val2 = fdp.ConsumeRandomLengthString();
	std::string content = fdp.ConsumeRemainingBytesAsString();

	log4cxx::LogString logger = LOG4CXX_STR("com.example.bar");
	log4cxx::LevelPtr level = log4cxx::Level::getInfo();
	std::string ndcMessage = "<envelope><faultstring><![CDATA[The EffectiveDate]]></faultstring><envelope>";
	log4cxx::NDC::push(ndcMessage);
	log4cxx::spi::LoggingEventPtr event = log4cxx::spi::LoggingEventPtr(
		new log4cxx::spi::LoggingEvent(
			logger, level, LOG4CXX_STR(content), LOG4CXX_LOCATION));

	// Set properties
	layout.setProperties(true);
	event->setProperty(LOG4CXX_STR(key1), LOG4CXX_STR(val1));

	// Set MDC
	log4cxx::MDC::put(key1, key2);

	// Location info
	layout.setLocationInfo(true);

	// Call the target API
	log4cxx::helpers::Pool p;
	log4cxx::LogString result;
	layout.format(result, event, p);

	// Clean up
	log4cxx::NDC::clear();
	log4cxx::MDC::clear();
  	return 0;
}
