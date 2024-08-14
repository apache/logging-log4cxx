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
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/appenderskeleton.h>

using namespace LOG4CXX_NS;

namespace LOG4CXX_NS::fuzzer {

/**
 * Appender encoding incoming log events using the provided layout.
 * It is intended for appender-agnostic fuzzing.
 */
class EncodingAppender : public AppenderSkeleton {

public:
	DECLARE_LOG4CXX_OBJECT(EncodingAppender)
	BEGIN_LOG4CXX_CAST_MAP()
	LOG4CXX_CAST_ENTRY(EncodingAppender)
	LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
	END_LOG4CXX_CAST_MAP()

	EncodingAppender() : AppenderSkeleton() {}

	EncodingAppender(const LayoutPtr& layout) : AppenderSkeleton(layout) {}

	void close() override {}

	bool requiresLayout() const override {
		return true;
	}

	void append(const spi::LoggingEventPtr& event, helpers::Pool& pool) override {
		LogString msg;
		getLayout()->format(msg, event, pool);
	}

	void activateOptions(helpers::Pool& pool) override {}

	void setOption(const LogString& option, const LogString& value) override {}

}; // class

IMPLEMENT_LOG4CXX_OBJECT(EncodingAppender)

LOG4CXX_PTR_DEF(EncodingAppender);

} // namespace

#define MAX_STRING_LENGTH 30

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	PropertyConfigurator::configure("PatternLayoutFuzzer.properties");
	LoggerPtr logger = Logger::getRootLogger();
  	FuzzedDataProvider dataProvider(data, size);
  	while (dataProvider.remaining_bytes() > 0) {
  		std::string message = dataProvider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    	LOG4CXX_INFO(logger, message);
    }
  	return 0;
}
