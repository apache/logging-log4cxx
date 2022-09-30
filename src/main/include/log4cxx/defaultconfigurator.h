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

#ifndef _LOG4CXX_DEFAULT_CONFIGURATOR_H
#define _LOG4CXX_DEFAULT_CONFIGURATOR_H

#include <log4cxx/spi/configurator.h>
#include <log4cxx/spi/loggerrepository.h>

namespace log4cxx
{

/**
 *   Configures the repository from environmental settings and files.
*
*/
class LOG4CXX_EXPORT DefaultConfigurator
{
	private:
		DefaultConfigurator() {}

	public:
		/**
		Configure \c repository.

		If the configuration file name has not been provided by a call to setConfigurationFileName(),
		the environment variables 'LOG4CXX_CONFIGURATION' and 'log4j.configuration' are examined.

		If the configuration file name has not been provided by any of the previous approaches
		the current directory is examined for a file named either
		"log4cxx.xml", "log4cxx.properties", "log4j.xml" or "log4j.properties".

		If a positive number has been provided by a call to setConfigurationWatchSeconds()
		or the environment variables 'LOG4CXX_CONFIGURATION_WATCH_SECONDS' contains a positive number
		a background thread is started that will periodically check for a change to the configuration file
		and apply any configuration changes found.
		.*/
		static void configure(spi::LoggerRepositoryPtr repository);

		/**
		Make \c path the configuration file used by configure().
		*/
		static void setConfigurationFileName(const LogString& path);

		/**
		Make \c seconds the time a background thread will delay before checking
		for a change to the configuration file used by configure().
		*/
		static void setConfigurationWatchSeconds(int seconds);

	private:
		static const LogString getConfigurationFileName();
		static const LogString getConfiguratorClass();
		static int getConfigurationWatchDelay();

};	 // class DefaultConfigurator
}  // namespace log4cxx

#endif //_LOG4CXX_DEFAULT_CONFIGURATOR_H
