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
// Fuzzer for the log4j-style properties configuration surface.
//
// The input is treated as a .properties configuration file and handed to
// PropertyConfigurator, mirroring what DOMConfiguratorFuzzer does for the
// XML configuration surface.  This is the sibling attack surface: a
// program's logging configuration drives class-registry instantiation
// (appenders, layouts, filters, rolling and triggering policies, error
// handlers), option conversion (OptionConverter variable substitution,
// integer/level/file-size parsing through helpers::Integer) and the
// log4j-properties text parser itself (helpers::Properties).
//
// After configuration, a bounded number of events is emitted through the
// configured appenders so that activateOptions()/append() paths execute
// (filter decisions, rollover triggers, syslog datagram send, console
// writers) rather than only the parsing front end.
//
// PropertyConfigurator::configure intentionally does not reset an existing
// configuration, so the harness resets the repository before and after to
// keep per-iteration resources (threads, sockets, file handles) bounded.
//
// Expected defect classes: memory safety in the properties parser and the
// class-registry instantiation path, integer parsing overflow
// (MaxFileSize/BufferSize/facility numbers), unbounded allocation from
// size-like options, and error-handling paths on malformed configurations.
//

#include <algorithm>
#include <cstdio>
#include <fuzzer/FuzzedDataProvider.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/mdc.h>
#include <log4cxx/ndc.h>
#include <log4cxx/net/syslogappender.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/propertyconfigurator.h>

using namespace log4cxx;

namespace
{
	const size_t MaximumFileByteCount = 100000;

	/**
	 * The configuration under test may leave an appender without a layout
	 * (e.g. a mistyped layout class name); SyslogAppender::append()
	 * dereferences the null layout and crashes (upstream issue log4cxx-1,
	 * see the findings directory).  Install a SimpleLayout on any layout-less
	 * appender so the events emitted below exercise the append paths rather
	 * than a known null-dereference.
	 */
	void giveLayoutlessAppendersALayout()
	{
		spi::LoggerRepositoryPtr repo = LogManager::getLoggerRepository();
		if (!repo)
		{
			return;
		}
		std::vector<LoggerPtr> loggers = repo->getCurrentLoggers();
		loggers.push_back(repo->getRootLogger());
		for (auto const& logger : loggers)
		{
			if (!logger)
			{
				continue;
			}
			AppenderList appenders = logger->getAllAppenders();
			for (auto const& appender : appenders)
			{
				if (appender && !appender->getLayout())
				{
					appender->setLayout(std::make_shared<SimpleLayout>());
				}
			}
		}
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char filename[16] = "conf.properties";

	// configure() does not reset the existing configuration; reset it here so
	// iterations cannot accumulate appenders (see propertyconfigurator.h).
	LogManager::resetConfiguration();

	FILE *fp = fopen(filename, "wb");
	if (!fp)
	{
		return 0;
	}
	fwrite(data, std::min(size, MaximumFileByteCount), 1, fp);
	fclose(fp);

	PropertyConfigurator::configure(filename);

	// Route around the known null-layout crash (findings/log4cxx-1) before
	// emitting events, so the gate validates the non-crashing remainder.
	giveLayoutlessAppendersALayout();

	// Emit a bounded number of events through whatever was configured.
	log4cxx::LoggerPtr logger = log4cxx::Logger::getRootLogger();
	log4cxx::MDC::put(LOG4CXX_STR("fuzzkey"), LOG4CXX_STR("fuzzvalue"));
	log4cxx::NDC::push(LOG4CXX_STR("fuzzndc"));
	LOG4CXX_INFO(logger, "property configurator fuzzer");
	LOG4CXX_DEBUG(logger, "second fuzz event");
	log4cxx::NDC::pop();
	log4cxx::MDC::remove(LOG4CXX_STR("fuzzkey"));

	LogManager::resetConfiguration();
	std::remove(filename);
	return 0;
}
