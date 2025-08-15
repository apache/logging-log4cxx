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
#include <log4cxx/logstring.h>
#include <log4cxx/defaultconfigurator.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/file.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/propertyconfigurator.h>


using namespace LOG4CXX_NS;
using namespace spi;
using namespace helpers;

namespace
{
	const LogString CONFIGURATION_FILE_KEY{ LOG4CXX_STR("LOG4CXX_CONFIGURATION") };
	const LogString WATCH_SECONDS_KEY{ LOG4CXX_STR("LOG4CXX_CONFIGURATION_WATCH_SECONDS") };
	const LogString CONFIGURATOR_CLASS_KEY{ LOG4CXX_STR("LOG4CXX_CONFIGURATOR_CLASS") };
#if LOG4CXX_VERSION_MAJOR <= 1
	const LogString LOG4J_CONFIGURATION_FILE_KEY{ LOG4CXX_STR("log4j.configuration") };
	const LogString LOG4J_CONFIGURATOR_CLASS_KEY{ LOG4CXX_STR("log4j.configuratorClass") };
#endif
}

void DefaultConfigurator::setConfigurationFileName(const LogString& path)
{
	Configurator::properties().setProperty(CONFIGURATION_FILE_KEY, path);
}

void DefaultConfigurator::setConfigurationWatchSeconds(int seconds)
{
	Pool p;
	LogString strSeconds;
	StringHelper::toString(seconds, p, strSeconds);
	Configurator::properties().setProperty(WATCH_SECONDS_KEY, strSeconds);
}

ConfigurationStatus DefaultConfigurator::tryConfigure()
{
	auto r = LogManager::getLoggerRepository();
	configure(r);
	return r->isConfigured() ? ConfigurationStatus::Configured : ConfigurationStatus::NotConfigured;
}

void DefaultConfigurator::configure(LoggerRepositoryPtr repository)
{

	LogString configurationFileName = getConfigurationFileName();
	Pool pool;
	File configuration;

	if (configurationFileName.empty())
	{
		LogString names[4] =
			{ LOG4CXX_STR("log4cxx.xml")
			, LOG4CXX_STR("log4cxx.properties")
			, LOG4CXX_STR("log4j.xml")
			, LOG4CXX_STR("log4j.properties")
			};

		for (int i = 0; i < 4; i++)
		{
			File candidate(names[i]);

			if (LogLog::isDebugEnabled())
			{
				LogString debugMsg = LOG4CXX_STR("Checking file ");
				debugMsg.append(names[i]);
				LogLog::debug(debugMsg);
			}
			if (candidate.exists(pool))
			{
				configuration = candidate;
				break;
			}
		}
	}
	else
	{
		configuration.setPath(configurationFileName);
	}

	if (configuration.exists(pool))
	{
		repository->setConfigured(true);
		if (LogLog::isDebugEnabled())
		{
			LogString msg(LOG4CXX_STR("Using configuration file ["));
			msg += configuration.getPath();
			msg += LOG4CXX_STR("] for automatic log4cxx configuration");
			LogLog::debug(msg);
		}

		LoggerRepositoryPtr repo(repository);
		OptionConverter::selectAndConfigure(
			configuration,
			getConfiguratorClass(),
			repo,
			getConfigurationWatchDelay()
			);
		// TBD: Report a failure
	}
	else if (LogLog::isDebugEnabled())
	{
		if (configurationFileName.empty())
		{
			LogLog::debug(LOG4CXX_STR("Could not find default configuration file."));
		}
		else
		{
			LogString msg(LOG4CXX_STR("Could not find configuration file: ["));
			msg += configurationFileName;
			msg += LOG4CXX_STR("].");
			LogLog::debug(msg);
		}
	}

}

const LogString DefaultConfigurator::getConfiguratorClass()
{
	auto result = System::getProperty(CONFIGURATOR_CLASS_KEY);
#if LOG4CXX_VERSION_MAJOR <= 1
	if (result.empty())
		result = System::getProperty(LOG4J_CONFIGURATOR_CLASS_KEY);
#endif
	return result;
}


const LogString DefaultConfigurator::getConfigurationFileName()
{
	auto& props = Configurator::properties();
	LogString configurationFileName = props.getProperty(CONFIGURATION_FILE_KEY);
	if (configurationFileName.empty())
		configurationFileName = System::getProperty(CONFIGURATION_FILE_KEY);
#if LOG4CXX_VERSION_MAJOR <= 1
	if (configurationFileName.empty())
		configurationFileName = System::getProperty(LOG4J_CONFIGURATION_FILE_KEY);
#endif
	return OptionConverter::substVars(configurationFileName, props);
}


int DefaultConfigurator::getConfigurationWatchDelay()
{
	LogString optionStr = Configurator::properties().getProperty(WATCH_SECONDS_KEY);
	if (optionStr.empty())
		optionStr = System::getProperty(WATCH_SECONDS_KEY);
	int milliseconds = 0;
	if (!optionStr.empty())
	{
		static const int MillisecondsPerSecond = 1000;
		milliseconds = StringHelper::toInt(optionStr) * MillisecondsPerSecond;
	}
	return milliseconds;
}

std::tuple<ConfigurationStatus,LogString>
DefaultConfigurator::configureFromFile(const std::vector<LogString>& directories, const std::vector<LogString>& filenames)
{
	using ResultType = std::tuple<ConfigurationStatus, LogString>;
	Pool pool;

	for (auto& dir : directories )
	{
		for (auto& fname : filenames )
		{
			auto candidate_str = dir + LOG4CXX_STR("/") + fname;
			File candidate(candidate_str);

			if (LogLog::isDebugEnabled())
				LogLog::debug(LOG4CXX_STR("Checking file ") + candidate_str);
			if (candidate.exists(pool))
			{
				setConfigurationFileName(candidate_str);
				auto configStatus = tryConfigure();
				if( configStatus == ConfigurationStatus::Configured )
					return ResultType{configStatus, candidate_str};
				if (LogLog::isDebugEnabled())
					LogLog::warn(LOG4CXX_STR("Unable to load: ") + candidate_str);
			}
		}
	}

	return ResultType{ConfigurationStatus::NotConfigured, LogString()};
}



