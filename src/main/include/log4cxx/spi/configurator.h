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

#ifndef _LOG4CXX_SPI_CONFIGURATOR_H
#define _LOG4CXX_SPI_CONFIGURATOR_H

#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/properties.h>

namespace LOG4CXX_NS
{
class File;

namespace spi
{

enum class ConfigurationStatus{
	Configured,
	NotConfigured,
};

/**
An abstract base for classes capable of configuring Log4cxx.
*/
class LOG4CXX_EXPORT Configurator : virtual public helpers::Object
{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Configurator)
#if 15 < LOG4CXX_ABI_VERSION
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Configurator)
		END_LOG4CXX_CAST_MAP()
#endif

		/**
		Read configuration from \c configFileName.
		If \c repository is not provided,
		the spi::LoggerRepository held by LogManager is used.

		@param configFileName The file to parse
		@param repository Holds the Logger instances.
		*/
		virtual ConfigurationStatus doConfigure
			( const File&                     configFileName
#if LOG4CXX_ABI_VERSION <= 15
			, spi::LoggerRepositoryPtr        repository
#else
			, const spi::LoggerRepositoryPtr& repository = spi::LoggerRepositoryPtr()
#endif
			) = 0;

		/**
		The key value pairs used when expanding ${varname} instances in a configuration file.

		By default, the map holds the currently executing program file path
		and the [std::filesystem::path](https://en.cppreference.com/w/cpp/filesystem/path.html)
		decomposition of the currently executing program file path, using the variable names:
		- PROGRAM_FILE_PATH
		- PROGRAM_FILE_PATH.ROOT_NAME
		- PROGRAM_FILE_PATH.ROOT_DIRECTORY
		- PROGRAM_FILE_PATH.ROOT_PATH
		- PROGRAM_FILE_PATH.RELATIVE_PATH
		- PROGRAM_FILE_PATH.PARENT_PATH
		- PROGRAM_FILE_PATH.FILENAME
		- PROGRAM_FILE_PATH.STEM
		- PROGRAM_FILE_PATH.EXTENSION
		*/
		static helpers::Properties& properties();

	protected:
		Configurator();

	private:
		Configurator(const Configurator&);
		Configurator& operator=(const Configurator&);
};

LOG4CXX_PTR_DEF(Configurator);
}
}

#endif // _LOG4CXX_SPI_CONFIGURATOR_H
