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
#include <log4cxx/fileappender.h>
#include <log4cxx/helpers/filesystempath.h>

using namespace LOG4CXX_NS;

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
#if !LOG4CXX_HAS_FILESYSTEM_PATH
				auto& props = spi::Configurator::properties();
				props.setProperty(LOG4CXX_STR("PROGRAM_FILE_PATH.STEM"), LOG4CXX_STR("defaultconfiguratortest"));
				props.setProperty(LOG4CXX_STR("PROGRAM_FILE_PATH.PARENT_PATH"), LOG4CXX_STR("output"));
#endif


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
		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("com.test"), logger->getName());
		auto comLogger = logger->getParent();
		LOGUNIT_ASSERT(comLogger);
		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("com"), comLogger->getName());
		auto rootLogger = comLogger->getParent();
		LOGUNIT_ASSERT(rootLogger);
		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR("root"), rootLogger->getName());
		auto appender = rootLogger->getAppender(LOG4CXX_STR("A1"));
		LOGUNIT_ASSERT(appender);
		auto fileAppender = LOG4CXX_NS::cast<FileAppender>(appender);
		LOGUNIT_ASSERT(fileAppender);
		LOGUNIT_ASSERT(fileAppender->getBufferedIO());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(DefaultConfiguratorTest);
