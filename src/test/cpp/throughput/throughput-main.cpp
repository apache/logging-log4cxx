/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/helpers/transcoder.h>

#include <string>
#include <thread>

#include <fmt/core.h>
#include <fmt/chrono.h>
#include <fmt/ostream.h>

#include "log4cxxbenchmarker.h"
using log4cxx::LogString;

static log4cxx::LoggerPtr console = log4cxx::Logger::getLogger( "console" );
static std::vector<uint64_t> results;

static void benchmark_function( const std::string& name, void (*fn)(int), int howmany )
{
	using std::chrono::duration;
	using std::chrono::duration_cast;
	using std::chrono::high_resolution_clock;

	auto start = high_resolution_clock::now();
	fn(howmany);
	auto delta = high_resolution_clock::now() - start;
	auto delta_d = duration_cast<duration<double>>(delta).count();

	results.push_back( uint64_t(howmany / delta_d) );
	LOG4CXX_INFO_FMT( console, "Log4cxx {} Elapsed: {:.4} secs {:L}/sec",
		name,
		delta_d,
		results.back() );
}

static void benchmark_conversion_pattern( const std::string& name,
	const std::string& conversion_pattern,
	void(*fn)(const LogString&, int),
	int howmany)
{
	using std::chrono::duration;
	using std::chrono::duration_cast;
	using std::chrono::high_resolution_clock;

	auto start = high_resolution_clock::now();
	LOG4CXX_DECODE_CHAR(conversion_patternLS, conversion_pattern);
	fn(conversion_patternLS, howmany);
	auto delta = high_resolution_clock::now() - start;
	auto delta_d = duration_cast<duration<double>>(delta).count();

	results.push_back( uint64_t(howmany / delta_d) );
	LOG4CXX_INFO_FMT( console, "Log4cxx {} pattern: {} Elapsed: {:.4} secs {:L}/sec",
		name,
		conversion_pattern,
		delta_d,
		results.back() );
}

static void bench_log4cxx_single_threaded(int iters)
{
	LOG4CXX_INFO(console, LOG4CXX_STR("**************************************************************"));
	LOG4CXX_INFO_FMT(console, "Benchmarking Single threaded: {} messages", iters );
	LOG4CXX_INFO(console, LOG4CXX_STR("**************************************************************"));

	benchmark_conversion_pattern( "NoFormat", "%m%n", &log4cxxbenchmarker::logWithConversionPattern, iters );
	benchmark_conversion_pattern( "DateOnly", "[%d] %m%n", &log4cxxbenchmarker::logWithConversionPattern, iters );
	benchmark_conversion_pattern( "DateClassLevel", "[%d] [%c] [%p] %m%n", &log4cxxbenchmarker::logWithConversionPattern, iters );

	benchmark_function( "Logging with FMT", &log4cxxbenchmarker::logWithFMT, iters );
	benchmark_function( "Logging static string", &log4cxxbenchmarker::logStaticString, iters );
	benchmark_function( "Logging static string with FMT", &log4cxxbenchmarker::logStaticStringFMT, iters );
	benchmark_function( "Logging disabled debug", &log4cxxbenchmarker::logDisabledDebug, iters );
	benchmark_function( "Logging disabled trace", &log4cxxbenchmarker::logDisabledTrace, iters );
	benchmark_function( "Logging enabled debug", &log4cxxbenchmarker::logEnabledDebug, iters );
	benchmark_function( "Logging enabled trace", &log4cxxbenchmarker::logEnabledTrace, iters );
}

static void bench_log4cxx_multi_threaded(size_t threads, int iters)
{
	LOG4CXX_INFO(console, LOG4CXX_STR("**************************************************************"));
	LOG4CXX_INFO_FMT(console, "Benchmarking multithreaded threaded: {} messages/thread, {} threads", iters, threads );
	LOG4CXX_INFO(console, LOG4CXX_STR("**************************************************************"));

	std::vector<std::thread> runningThreads;

	auto logger = log4cxxbenchmarker::logSetupMultithreaded();

	for ( size_t x = 0; x < threads; x++ )
	{
		runningThreads.push_back( std::thread( [iters]()
		{
			benchmark_function( "Logging with FMT MT", &log4cxxbenchmarker::logWithFMTMultithreaded, iters );
		}) );
	}

	for ( std::thread& th : runningThreads )
	{
		th.join();
	}
}

static void bench_log4cxx_multi_threaded_disabled(size_t threads, int iters)
{
	LOG4CXX_INFO(console, LOG4CXX_STR("**************************************************************"));
	LOG4CXX_INFO_FMT(console, "Benchmarking multithreaded disabled: {} messages/thread, {} threads", iters, threads );
	LOG4CXX_INFO(console, LOG4CXX_STR("**************************************************************"));

	std::vector<std::thread> runningThreads;

	auto logger = log4cxxbenchmarker::logSetupMultithreaded();

	for ( size_t x = 0; x < threads; x++ )
	{
		runningThreads.push_back( std::thread( [iters]()
		{
			benchmark_function( "Logging disabled MT", &log4cxxbenchmarker::logDisabledMultithreaded, iters );
		}) );
	}

	for ( std::thread& th : runningThreads )
	{
		th.join();
	}
}

int main(int argc, char* argv[])
{
	int iters = 1000000;
	size_t threads = 4;
	size_t max_threads = 32;

	std::setlocale( LC_ALL, "" ); /* Set locale for C functions */
	std::locale::global(std::locale("")); /* set locale for C++ functions */

	console->setAdditivity( false );
	log4cxx::PatternLayoutPtr pattern( new log4cxx::PatternLayout() );
	pattern->setConversionPattern( LOG4CXX_STR("%m%n") );

	log4cxx::ConsoleAppenderPtr consoleWriter( new log4cxx::ConsoleAppender );
	consoleWriter->setLayout( pattern );
	consoleWriter->setTarget( LOG4CXX_STR("System.out") );
	log4cxx::helpers::Pool p;
	consoleWriter->activateOptions(p);

	console->addAppender( consoleWriter );

	if (argc > 1)
	{
		iters = std::stoi(argv[1]);
	}

	if (argc > 2)
	{
		threads = std::stoul(argv[2]);
	}

	if (threads > max_threads)
	{
		LOG4CXX_ERROR_FMT(console, "Too many threads specified(max: {})", max_threads);
		return 1;
	}

	LOG4CXX_INFO_FMT(console, "Benchmarking library only(no writing out):");
	bench_log4cxx_single_threaded(iters);
	bench_log4cxx_multi_threaded(threads, iters);
	bench_log4cxx_multi_threaded_disabled(threads, iters);

	LOG4CXX_INFO_FMT(console, "Results for use in spreadsheet:");

	for ( uint64_t result : results )
	{
		LOG4CXX_INFO_FMT(console, "{}", result );
	}

	return 0;
}
