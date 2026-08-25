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
#include "logunit.h"
#include <log4cxx/logmanager.h>
#include <log4cxx/defaultconfigurator.h>
#include <log4cxx/basicconfigurator.h>

using namespace log4cxx;

namespace
{
	auto GetLogger(const std::string& name) -> LoggerPtr
	{
		static struct log4cxx_initializer
		{
			log4cxx_initializer()
			{
				// Check every 5 seconds for configuration file changes
				DefaultConfigurator::setConfigurationWatchSeconds(5);

				// Look for a configuration file in the current working directory
				// and the same directory as the program
				std::vector<LogString> paths
					{ LOG4CXX_STR("input")
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
			~log4cxx_initializer()
			{
				LogManager::shutdown();
			}
		} initialiser;
		return name.empty()
			? LogManager::getRootLogger()
			: LogManager::getLogger(name);
	}

	auto logger = GetLogger("com.test");
}

LOGUNIT_CLASS(DefaultConfiguratorTest)
{
	LOGUNIT_TEST_SUITE(DefaultConfiguratorTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST_SUITE_END();
public:

	void test1()
	{
		LOGUNIT_ASSERT(logger);
		LOGUNIT_ASSERT(logger->isDebugEnabled());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(DefaultConfiguratorTest);
