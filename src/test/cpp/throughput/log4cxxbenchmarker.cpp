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

namespace log4cxx
{

class NullWriterAppender : public log4cxx::AppenderSkeleton
{
	public:
		DECLARE_LOG4CXX_OBJECT(NullWriterAppender)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(NullWriterAppender)
		LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

		NullWriterAppender() {}

		virtual void close() {}

		virtual bool requiresLayout() const
		{
			return true;
		}

		virtual void append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p)
		{
			// This gets called whenever there is a valid event for our appender.
		}

		virtual void activateOptions(log4cxx::helpers::Pool& /* pool */)
		{
			// Given all of our options, do something useful(e.g. open a file)
		}

		virtual void setOption(const LogString& option, const LogString& value)
		{
		}
};

IMPLEMENT_LOG4CXX_OBJECT(NullWriterAppender)

LOG4CXX_PTR_DEF(NullWriterAppender);

}

log4cxxbenchmarker::log4cxxbenchmarker()
{

}

log4cxx::LoggerPtr log4cxxbenchmarker::resetLogger()
{
	log4cxx::LoggerPtr logger = log4cxx::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( log4cxx::Level::getInfo() );

	log4cxx::PatternLayoutPtr pattern = std::make_shared<log4cxx::PatternLayout>();
	pattern->setConversionPattern( LOG4CXX_STR("%m%n") );

	log4cxx::NullWriterAppenderPtr nullWriter = std::make_shared<log4cxx::NullWriterAppender>();
	nullWriter->setLayout( pattern );

	logger->addAppender( nullWriter );

	return logger;
}

void log4cxxbenchmarker::logWithConversionPattern( const log4cxx::LogString& conversionPattern, int howmany )
{
	log4cxx::LoggerPtr logger = log4cxx::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( log4cxx::Level::getInfo() );

	log4cxx::PatternLayoutPtr pattern = std::make_shared<log4cxx::PatternLayout>();
	pattern->setConversionPattern( conversionPattern );

	log4cxx::NullWriterAppenderPtr nullWriter = std::make_shared<log4cxx::NullWriterAppender>();
	nullWriter->setLayout( pattern );

	logger->addAppender( nullWriter );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("Hello logger: msg number ") << x);
	}
}

void log4cxxbenchmarker::logWithFMT(int howmany)
{
	log4cxx::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", x);
	}
}

log4cxx::LoggerPtr log4cxxbenchmarker::logSetupMultithreaded()
{
	log4cxx::LoggerPtr logger = log4cxx::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	logger->removeAllAppenders();
	logger->setAdditivity( false );
	logger->setLevel( log4cxx::Level::getInfo() );

	log4cxx::PatternLayoutPtr pattern = std::make_shared<log4cxx::PatternLayout>();
	pattern->setConversionPattern( LOG4CXX_STR("%m%n") );

	log4cxx::NullWriterAppenderPtr nullWriter = std::make_shared<log4cxx::NullWriterAppender>();
	nullWriter->setLayout( pattern );

	logger->addAppender( nullWriter );
	return logger;
}

void log4cxxbenchmarker::logWithFMTMultithreaded(int howmany)
{
	log4cxx::LoggerPtr logger = log4cxx::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO_FMT( logger, "Hello logger: msg number {}", x);
	}
}

void log4cxxbenchmarker::logDisabledMultithreaded( int howmany )
{
	log4cxx::LoggerPtr logger = log4cxx::Logger::getLogger( LOG4CXX_STR("bench_logger") );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_TRACE( logger, LOG4CXX_STR("Hello logger!  What is happening"));
	}
}

void log4cxxbenchmarker::logStaticString( int howmany )
{
	log4cxx::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logStaticStringFMT( int howmany )
{
	log4cxx::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_INFO_FMT( logger, "This is a static string to see what happens");
	}
}

void log4cxxbenchmarker::logDisabledDebug( int howmany )
{
	log4cxx::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logDisabledTrace( int howmany )
{
	log4cxx::LoggerPtr logger = resetLogger();

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_TRACE( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logEnabledDebug( int howmany )
{
	log4cxx::LoggerPtr logger = resetLogger();
	logger->setLevel( log4cxx::Level::getDebug() );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}

void log4cxxbenchmarker::logEnabledTrace( int howmany )
{
	log4cxx::LoggerPtr logger = resetLogger();
	logger->setLevel( log4cxx::Level::getTrace() );

	for ( int x = 0; x < howmany; x++ )
	{
		LOG4CXX_DEBUG( logger, LOG4CXX_STR("This is a static string to see what happens"));
	}
}
