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
#include "config.h"
#include "product_version.h"
#include <log4cxx/logmanager.h>
#include <log4cxx/defaultconfigurator.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/helpers/transcoder.h>
#include <vector>

namespace com { namespace foo {

// Retrieve the \c name logger pointer.
// Configure Log4cxx on the first call.
auto getLogger(const std::string& name) -> LoggerPtr {
	using namespace log4cxx;
	static struct log4cxx_initializer {
		log4cxx_initializer() {
			auto vendorFolder = getVendorFolder();
			auto productFolder = getProductFolder();
			LOG4CXX_DECODE_CHAR(lsVendorFolder, vendorFolder);
			LOG4CXX_DECODE_CHAR(lsProductFolder, productFolder);

			// Allow expansion of ${CURRENT_VENDOR_FOLDER} and ${CURRENT_PRODUCT_FOLDER}
			// when loading a configuration from a file
			auto& props = spi::Configurator::properties();
			props.setProperty(LOG4CXX_STR("CURRENT_VENDOR_FOLDER"), lsVendorFolder);
			props.setProperty(LOG4CXX_STR("CURRENT_PRODUCT_FOLDER"), lsProductFolder);

			// Check every 5 seconds for configuration file changes
			DefaultConfigurator::setConfigurationWatchSeconds(5);

			// Look for a configuration file in the current working directory
			// and the same directory as the program
			std::vector<LogString> paths
				{ LOG4CXX_STR(".")
				, LOG4CXX_STR("${PROGRAM_FILE_PATH.PARENT_PATH}")
				};
			std::vector<LogString> names
				{ LOG4CXX_STR("${PROGRAM_FILE_PATH.STEM}.xml")
				, LOG4CXX_STR("${PROGRAM_FILE_PATH.STEM}.properties")
				};
			auto status       = spi::ConfigurationStatus::NotConfigured;
			auto selectedPath = LogString();
			std::tie(status, selectedPath) = DefaultConfigurator::configureFromFile(paths, names);
			if (status == spi::ConfigurationStatus::NotConfigured)
				BasicConfigurator::configure(); // Send events to the console
		}
		~log4cxx_initializer() {
			LogManager::shutdown();
		}
	} initialiser;
	return name.empty()
		? LogManager::getRootLogger()
		: LogManager::getLogger(name);
}

} } // namespace com::foo
