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
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>

using namespace LOG4CXX_NS;
using namespace spi;
using namespace helpers;

void DefaultConfigurator::setConfigurationFileName(const LogString& path)
{
	Configurator::properties().setProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATION"), path);
}

void DefaultConfigurator::setConfigurationWatchSeconds(int seconds)
{
	Pool p;
	LogString strSeconds;
	StringHelper::toString(seconds, p, strSeconds);
	Configurator::properties().setProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATION_WATCH_SECONDS"), strSeconds);
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
	auto result = System::getProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATOR_CLASS"));
#if LOG4CXX_VERSION_MAJOR <= 1
	if (result.empty())
		result = System::getProperty(LOG4CXX_STR("log4j.configuratorClass"));
#endif
	return result;
}


const LogString DefaultConfigurator::getConfigurationFileName()
{
	auto& props = Configurator::properties();
	LogString configurationFileName = props.getProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATION"));
	bool isEnvVar = false;
	if (configurationFileName.empty())
	{
		configurationFileName = System::getProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATION"));
		isEnvVar = true;
	}
#if LOG4CXX_VERSION_MAJOR <= 1
	if (configurationFileName.empty())
	{
		configurationFileName = System::getProperty(LOG4CXX_STR("log4j.configuration"));
		isEnvVar = true;
	}
#endif
#if !LOG4CXX_EXPAND_CONFIG_ENV_VAR
	if (isEnvVar)
		return configurationFileName;
#endif
	try
	{
		return OptionConverter::substVars(configurationFileName, props);
	}
	catch (IllegalArgumentException& e)
	{
		LogLog::warn(LOG4CXX_STR("Could not perform variable substitution."), e);
		return configurationFileName;
	}
}


int DefaultConfigurator::getConfigurationWatchDelay()
{
	LogString optionStr = Configurator::properties().getProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATION_WATCH_SECONDS"));
	if (optionStr.empty())
		optionStr = System::getProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATION_WATCH_SECONDS"));
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
	auto result = std::tuple<ConfigurationStatus, LogString>
		{ ConfigurationStatus::NotConfigured, LogString() };
	auto r = LogManager::getLoggerRepository();
	Pool pool;

	for (auto& dir : directories )
	{
		for (auto& fname : filenames )
		{
			setConfigurationFileName(dir + LOG4CXX_STR("/") + fname);
			auto candidate_str = getConfigurationFileName();
			File candidate(candidate_str);

			if (LogLog::isDebugEnabled())
				LogLog::debug(LOG4CXX_STR("Checking file ") + candidate_str);
			if (candidate.exists(pool))
			{
				std::get<1>(result) = candidate_str;
				configure(r);
				if (r->isConfigured())
				{
					std::get<0>(result) = ConfigurationStatus::Configured;
					return result;
				}
			}
		}
	}
	return result;
}
