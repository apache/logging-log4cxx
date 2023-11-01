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
#ifndef LOG4CXXBENCHMARKER_H
#define LOG4CXXBENCHMARKER_H

#include <string>

#include <log4cxx/logger.h>

class log4cxxbenchmarker
{
	private:
		log4cxxbenchmarker();

		static log4cxx::LoggerPtr resetLogger();

	public:
		/**
		 * Given a conversion pattern, send a number of log messages to the logger.  INFO level.
		 *
		 * Log message format: "Hello logger: msg number " << x
		 *
		 * @param conversionPattern The conversion pattern used, as passed to the PatternLayout
		 */
		static void logWithConversionPattern( const log4cxx::LogString& conversionPattern, int howmany );

		/**
		 * Log with the LOG4CXX_INFO_FMT macro to see how long it takes.
		 * This does a single parameter replacement with libfmt(the same message as logWithConversionPattern)
		 *
		 * @param howmany
		 */
		static void logWithFMT( int howmany );

		/**
		 * Reset logger for multithreaded setup.
		 */
		static log4cxx::LoggerPtr logSetupMultithreaded();

		/**
		 * Log with the LOG4CXX_INFO_FMT macro to see how long it takes(multithreaded).
		 * @param howmany
		 */
		static void logWithFMTMultithreaded( int howmany );

		/**
		 * Log messages in a multithreaded manner, but at a TRACE level
		 * so they will be disabled.
		 *
		 * @param howmany
		 */
		static void logDisabledMultithreaded( int howmany );

		/**
		 * Log a string that doesn't use operator<< any place.
		 * Logs at INFO level
		 *
		 * String to log: "This is a static string to see what happens"
		 * @param howmany
		 */
		static void logStaticString( int howmany );

		/**
		* Log a string that doesn't use operator<< any place, but uses libfmt.
		* Logs at INFO level
		*
		* String to log: "This is a static string to see what happens"
		* @param howmany
		*/
		static void logStaticStringFMT( int howmany );

		/**
		 * Log a message at the DEBUG level, with debug disabled.
		 */
		static void logDisabledDebug( int howmany );

		/**
		 * Log a message at the TRACE level, with trace disabled.
		 */
		static void logDisabledTrace( int howmany );

		/**
		 * Log a message at the DEBUG level, with debug enabled.
		 */
		static void logEnabledDebug( int howmany );

		/**
		 * Log a message at the TRACE level, with trace enabled.
		 */
		static void logEnabledTrace( int howmany );
};

#endif // LOG4CXXBENCHMARKER_H
