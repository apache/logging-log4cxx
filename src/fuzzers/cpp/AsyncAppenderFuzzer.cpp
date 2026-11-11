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
// Fuzzer for AsyncAppender: the ring-buffer queue, the dispatcher thread and
// the close/shutdown path (AsyncAppenderPriv::dispatch, AsyncBuffer,
// CyclicBuffer, ThreadUtility).
//
// The producer side is driven with fuzzed BufferSize/Blocking settings, a
// bounded event count and an optional early close(), i.e. the
// dispatcher races a close while events are still pending - the classic
// use-after-free/double-release shape for async logging queues.  The sink is
// a counting appender with a PatternLayout so the dispatcher thread formats
// events (message buffer, MDC/NDC and, for half of the inputs, location
// information conversion) without doing I/O.
//
// Everything is rebuilt per iteration and the repository is reset at the
// end, so appender, thread and queue lifetimes stay per-iteration bounded.
//
// Expected defect classes: use-after-free / double-free between close() and
// the dispatcher, unbounded queue growth (OOM), lost-wake-up hangs, and
// leaks when close is skipped while events are pending.
//

#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/asyncappender.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/mdc.h>
#include <log4cxx/ndc.h>
#include <log4cxx/patternlayout.h>

using namespace log4cxx;

namespace LOG4CXX_NS::fuzzer {

/**
 * I/O-free sink appender; formats each event in the dispatcher thread.
 */
class FormattingSinkAppender : public AppenderSkeleton {

public:

	DECLARE_LOG4CXX_OBJECT(FormattingSinkAppender)
	BEGIN_LOG4CXX_CAST_MAP()
	LOG4CXX_CAST_ENTRY(FormattingSinkAppender)
	LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
	END_LOG4CXX_CAST_MAP()

	FormattingSinkAppender() : AppenderSkeleton() {}

	FormattingSinkAppender(const LayoutPtr& layout) : AppenderSkeleton(layout) {}

	void append( const spi::LoggingEventPtr& event ) override {
		LogString formatted;
		getLayout()->format(formatted, event);
	}

	void setOption(const LogString& option, const LogString& value) override {}

}; // class

IMPLEMENT_LOG4CXX_OBJECT(FormattingSinkAppender)

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	FuzzedDataProvider fdp(data, size);

	int bufferSize = fdp.ConsumeIntegralInRange<int>(1, 128);
	bool blocking = fdp.ConsumeBool();
	bool locationInfo = fdp.ConsumeBool();
	int eventCount = fdp.ConsumeIntegralInRange<int>(1, 32);
	bool closeEarly = fdp.ConsumeBool();

	AsyncAppenderPtr async(new AsyncAppender());
	async->setName(LOG4CXX_STR("fuzz-async"));
	async->setBufferSize(bufferSize);
	async->setBlocking(blocking);

	// AsyncAppender has no LocationInfo option; when the fuzzed flag is set,
	// the dispatcher thread formats the events' location information
	// through the %l conversion of the sink's pattern layout instead.
	PatternLayoutPtr layout(new PatternLayout(
		locationInfo
			? LOG4CXX_STR("%p %c{1} [%t] %X{fuzzkey} %J{fuzzkey} %x %l %m%n")
			: LOG4CXX_STR("%p %c{1} [%t] %X{fuzzkey} %J{fuzzkey} %x %m%n")));
	LayoutPtr sinkLayout = layout;
	async->addAppender(std::make_shared<LOG4CXX_NS::fuzzer::FormattingSinkAppender>(sinkLayout));

	LoggerPtr logger = Logger::getLogger(LOG4CXX_STR("fuzz.async"));
	logger->addAppender(async);

	MDC::put(LOG4CXX_STR("fuzzkey"), LOG4CXX_STR("fuzzvalue"));
	NDC::push(LOG4CXX_STR("fuzzndc"));

	for (int i = 0; i < eventCount; i++)
	{
		if (closeEarly && i == eventCount / 2)
		{
			// Race the dispatcher: events may still be pending.
			async->close();
		}
		LOG4CXX_INFO(logger, "async appender fuzz event");
	}

	async->close();
	logger->removeAppender(async);
	NDC::pop();
	MDC::remove(LOG4CXX_STR("fuzzkey"));
	LogManager::resetConfiguration();

	return 0;
}
