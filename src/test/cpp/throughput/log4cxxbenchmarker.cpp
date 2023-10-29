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
#include "log4cxxbenchmarker.h"

#include <log4cxx/logger.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/appenderskeleton.h>

#include <fmt/format.h>

namespace LOG4CXX_NS
{

class NullWriterAppender : public LOG4CXX_NS::AppenderSkeleton
{
	public:
		DECLARE_LOG4CXX_OBJECT(NullWriterAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(NullWriterAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		NullWriterAppender() {}

		void close() override {}

		bool requiresLayout() const override
		{
			return true;
		}

		void append(const spi::LoggingEventPtr& event, LOG4CXX_NS::helpers::Pool& p) override
		{
			// This gets called whenever there is a valid event for our appender.
		}

		void activateOptions(LOG4CXX_NS::helpers::Pool& /* pool */) override
		{
			// Given all of our options, do something useful(e.g. open a file)
		}

		void setOption(const LogString& option, const LogString& value) override
		{
		}
};

IMPLEMENT_LOG4CXX_OBJECT(NullWriterAppender)

LOG4CXX_PTR_DEF(NullWriterAppender);

}

log4cxxbenchmarker::log4cxxbenchmarker()
{

}

LOG4CXX_NS::LoggerPtr log4cxxbenchmarker::resetLogger()
{
	LOG4CXX_NS::LoggerPtr logger = LOG4CXX_NS::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( LOG4CXX_NS::Level::getInfo() );

	LOG4CXX_NS::PatternLayoutPtr pattern = std::make_shared<LOG4CXX_NS::PatternLayout>();
	pattern->setConversionPattern( LOG4CXX_STR("%m%n") );

	LOG4CXX_NS::NullWriterAppenderPtr nullWriter = std::make_shared<LOG4CXX_NS::NullWriterAppender>();
	nullWriter->setLayout( pattern );

	logger->addAppender( nullWriter );

	return logger;
}

void log4cxxbenchmarker::logWithConversionPattern( const LOG4CXX_NS::LogString& conversionPattern, int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = LOG4CXX_NS::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( LOG4CXX_NS::Level::getInfo() );

	LOG4CXX_NS::PatternLayoutPtr pattern = std::make_shared<LOG4CXX_NS::PatternLayout>();
	pattern->setConversionPattern( conversionPattern );

	LOG4CXX_NS::NullWriterAppenderPtr nullWriter = std::make_shared<LOG4CXX_NS::NullWriterAppender>();
	nullWriter->setLayout( pattern );

	logger->addAppender( nullWriter );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("Hello logger: msg number ") << x);
	}
}

void log4cxxbenchmarker::logWithFMT(int howmany)
{
	LOG4CXX_NS::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", x);
	}
}

LOG4CXX_NS::LoggerPtr log4cxxbenchmarker::logSetupMultithreaded()
{
	LOG4CXX_NS::LoggerPtr logger = LOG4CXX_NS::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( LOG4CXX_NS::Level::getInfo() );

	LOG4CXX_NS::PatternLayoutPtr pattern = std::make_shared<LOG4CXX_NS::PatternLayout>();
	pattern->setConversionPattern( LOG4CXX_STR("%m%n") );

	LOG4CXX_NS::NullWriterAppenderPtr nullWriter = std::make_shared<LOG4CXX_NS::NullWriterAppender>();
	nullWriter->setLayout( pattern );

	logger->addAppender( nullWriter );
	return logger;
}

void log4cxxbenchmarker::logWithFMTMultithreaded(int howmany)
{
	LOG4CXX_NS::LoggerPtr logger = LOG4CXX_NS::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", x);
	}
}

void log4cxxbenchmarker::logDisabledMultithreaded( int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = LOG4CXX_NS::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_TRACE( logger, LOG4CXX_STR("Hello logger!  What is happening"));
	}
}

void log4cxxbenchmarker::logStaticString( int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logStaticStringFMT( int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO_FMT( logger, "This is a static string to see what happens");
	}
}

void log4cxxbenchmarker::logDisabledDebug( int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logDisabledTrace( int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_TRACE( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logEnabledDebug( int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = resetLogger();
	logger->setLevel( LOG4CXX_NS::Level::getDebug() );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logEnabledTrace( int howmany )
{
	LOG4CXX_NS::LoggerPtr logger = resetLogger();
	logger->setLevel( LOG4CXX_NS::Level::getTrace() );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
