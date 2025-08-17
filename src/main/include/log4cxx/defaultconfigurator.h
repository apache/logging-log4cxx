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
#include <tuple>

namespace LOG4CXX_NS
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
		the environment variable "LOG4CXX_CONFIGURATION" or "log4j.configuration" value is used,
		with ${varname} instances using either a system environment variable value (if found)
		otherwise using the helpers::Properties object
		provided by spi::Configurator::properties.

		\usage
		~~~
		setenv LOG4CXX_CONFIGURATION="${PROGRAM_FILE_PATH.PARENT_PATH}/${PROGRAM_FILE_PATH.STEM}.xml"
		~~~

		Unless a custom configurator is specified using the
		"LOG4CXX_CONFIGURATOR_CLASS" or "log4j.configuratorClass"
		environment variable, the PropertyConfigurator will be used to
		configure log4cxx unless the file name ends with the ".xml"
		extension, in which case the DOMConfigurator will be used. If a
		custom configurator is specified, the environment variable should
		contain a fully qualified class name of a class that implements the
		Configurator interface.

		If the configuration file name is not found using any of the previous approaches,
		the current directory is examined for a file with extension ".xml" or ".properties"
		with a base name "log4cxx" or "log4j".

		If a positive number has been provided by a call to setConfigurationWatchSeconds()
		or the environment variables "LOG4CXX_CONFIGURATION_WATCH_SECONDS" contains a positive number
		a background thread is started that will periodically check for a change to the configuration file
		and apply any configuration changes found.

		Call the spi::LoggerRepository::isConfigured \c repository member function
		to determine whether a configuration file was found.
		*/
		static void configure(spi::LoggerRepositoryPtr repository);

		/**
		Attempt configuration by calling configure() passing the default repository.

		See configure() for how the configuration file name is determined.

		@return a success indicator.
		*/
		static spi::ConfigurationStatus tryConfigure();

		/**
		Make \c path the configuration file used by configure().

		Any ${varname} instances in the \c path value are expanded
		using either a system environment variable value (if found)
		otherwise using the map provided by spi::Configurator::properties.

		\usage
		~~~{.cpp}
		DefaultConfigurator::setConfigurationFileName(LOG4CXX_STR("${PROGRAM_FILE_PATH.PARENT_PATH}/${PROGRAM_FILE_PATH.STEM}.xml"))
		~~~

		*/
		static void setConfigurationFileName(const LogString& path);

		/**
		Make \c seconds the time a background thread will delay before checking
		for a change to the configuration file used by configure().

		\usage
		~~~{.cpp}
		DefaultConfigurator::setConfigurationWatchSeconds(1);
		~~~
		*/
		static void setConfigurationWatchSeconds(int seconds);

		/**
		 * Call configure() passing the default repository
		 * after calling setConfigurationFileName() with a path composed of
		 * an entry in \c directories and an entry in \c filenames
		 * when the combination identifies an existing file.
		 *
		 \usage
		 ~~~{.cpp}
		 std::vector<LogString> directories
		     { LOG4CXX_STR(".")
		     , LOG4CXX_STR("${PROGRAM_FILE_PATH.PARENT_PATH}")
		     };
		 std::vector<LogString> filenames
		     { LOG4CXX_STR("${PROGRAM_FILE_PATH.STEM}.xml")
		     , LOG4CXX_STR("${PROGRAM_FILE_PATH.STEM}.properties")
		     };
		 DefaultConfigurator::configureFromFile(directories, filenames);
		 ~~~
		 *
		 * For example, given a "myapp" executable file name
		 * run from the "/opt/com.foo/bin" directory,
		 * locations are checked in the following order:
		 *
		 * <pre>
		 * ./myapp.xml
		 * ./myapp.properties
		 * /opt/com.foo/bin/myapp.xml
		 * /opt/com.foo/bin/myapp.properties
		 * </pre>
		 *
		 * If a file exists but it is not able to be used to configure Log4cxx,
		 * the next file in the combinatorial set will be tried until
		 * a valid configuration file is found or
		 * all values in the combinatorial set have been tried.
		 *
		 * @param directories The directories to look in.
		 * @param filenames The names of the files to look for
		 * @return a success indicator and the configuration file path that was used (if found).
		 */
		static std::tuple<spi::ConfigurationStatus,LogString> configureFromFile
			( const std::vector<LogString>& directories
			, const std::vector<LogString>& filenames
			);

	private:
		static const LogString getConfigurationFileName();
		static const LogString getConfiguratorClass();
		static int getConfigurationWatchDelay();

};	 // class DefaultConfigurator
}  // namespace log4cxx

#endif //_LOG4CXX_DEFAULT_CONFIGURATOR_H
