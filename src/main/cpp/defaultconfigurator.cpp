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
#include <log4cxx/helpers/pool.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/file.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>
#include <limits.h> // MAX_PATH
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>
#ifdef WIN32
#include <Windows.h>
#elif __APPLE__
#include <mach-o/dyld.h>
#else
#include <unistd.h>     /* getpid */
#endif

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

namespace
{
	LogString DefaultConfiguratorPath;
	int DefaultConfiguratorWatchSeconds = 0;

	// Get a list of file base names that may contain configuration data
	// and put an alternate path into \c altPrefix
	std::vector<std::string> DefaultConfigurationFileNames(std::string& altPrefix)
	{
		std::vector<std::string> result;
		result.push_back("log4cxx");
		result.push_back("log4j");

        // Add executable base name
		static const int bufSize = MAX_PATH;
		char buf[bufSize+1] = {0}, pathSepar = '/';
        uint32_t bufCount = 0;
#ifdef WIN32
		GetModuleFileName(NULL, buf, bufSize);
		pathSepar = '\\';
#elif defined(__APPLE__)
		_NSGetExecutablePath(buf, &bufCount);
#elif LOG4CXX_HAS_READLINK
		std::ostringstream exeLink;
		exeLink << "/proc/" << getpid() << "/exe";
		bufCount = readlink(exeLink.str().c_str(), buf, bufSize);
		if (0 < bufCount)
			buf[bufCount] = 0;
#endif
		std::string programFileName(buf);
        auto slashIndex = programFileName.rfind(pathSepar);
		if (std::string::npos != slashIndex)
        {
            // Extract the path
            altPrefix = programFileName.substr(0, slashIndex + 1);
            LogString msg1 = LOG4CXX_STR("Alternate prefix [");
            helpers::Transcoder::decode(altPrefix, msg1);
            msg1 += LOG4CXX_STR("]");
            LogLog::debug(msg1);
            // Add a local directory relative name
            result.push_back(programFileName.substr(slashIndex + 1));
            LogString msg2(LOG4CXX_STR("Alternate configuration file name ["));
            helpers::Transcoder::decode(result.back(), msg2);
            msg2 += LOG4CXX_STR("]");
            LogLog::debug(msg2);
            // Add a local directory relative name without any extension
			auto dotIndex = result.back().rfind('.');
			if (std::string::npos != dotIndex)
            {
                auto dotIndex = result.back().rfind('.');
                if (std::string::npos != dotIndex)
                {
                    result.push_back(result.back());
                    result.back().erase(dotIndex);
                    LogString msg3(LOG4CXX_STR("Alternate configuration file name ["));
                    helpers::Transcoder::decode(result.back(), msg3);
                    msg3 += LOG4CXX_STR("]");
                    LogLog::debug(msg3);
                }
            }
        }
		else if (!programFileName.empty())
		{
			auto dotIndex = result.back().rfind('.');
			if (std::string::npos != dotIndex)
            {
				programFileName.erase(dotIndex);
                result.push_back(programFileName);
                LogString msg(LOG4CXX_STR("Alternate configuration file name ["));
                helpers::Transcoder::decode(result.back(), msg);
                msg += LOG4CXX_STR("]");
                LogLog::debug(msg);
            }
		}
		return result;
	}
}

void DefaultConfigurator::setConfigurationFileName(const LogString& path)
{
	DefaultConfiguratorPath = path;
}


void DefaultConfigurator::setConfigurationWatchSeconds(int seconds)
{
	DefaultConfiguratorWatchSeconds = seconds;
}

static const int MillisecondsPerSecond = 1000;

void DefaultConfigurator::configure(LoggerRepositoryPtr repository)
{
	repository->setConfigured(true);
	const LogString configuratorClassName(getConfiguratorClass());

	LogString configurationFileName = DefaultConfiguratorPath;
	if (configurationFileName.empty())
		configurationFileName = getConfigurationFileName();
	Pool pool;
	File configuration;

	if (configurationFileName.empty())
	{
		const char* extension[] = { ".xml", ".properties", 0 };
		std::string altPrefix;

		for (auto baseName : DefaultConfigurationFileNames(altPrefix))
		{
			int i = 0;
			for (; extension[i]; ++i)
			{
				File current_working_dir_candidate(baseName + extension[i]);
				if (current_working_dir_candidate.exists(pool))
				{
					configuration = current_working_dir_candidate;
					break;
				}
				if (!altPrefix.empty())
				{
				    File alt_dir_candidate(altPrefix + baseName + extension[i]);
				    if (alt_dir_candidate.exists(pool))
				    {
				        configuration = alt_dir_candidate;
				        break;
				    }
				}
			}
			if (extension[i]) // Found a configuration file?
				break;
		}
	}
	else
	{
		configuration.setPath(configurationFileName);
	}

	if (configuration.exists(pool))
	{
		LogString msg(LOG4CXX_STR("Using configuration file ["));
		msg += configuration.getPath();
		msg += LOG4CXX_STR("] for automatic log4cxx configuration");
		LogLog::debug(msg);

		LoggerRepositoryPtr repo(repository);
		OptionConverter::selectAndConfigure(
			configuration,
			configuratorClassName,
			repo,
			0 < DefaultConfiguratorWatchSeconds
				? DefaultConfiguratorWatchSeconds * MillisecondsPerSecond
				: getConfigurationWatchDelay()
			);
	}
	else
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

	// Use automatic configration to configure the default hierarchy
	const LogString log4jConfiguratorClassName(
		OptionConverter::getSystemProperty(LOG4CXX_STR("log4j.configuratorClass"), LOG4CXX_STR("")));
	const LogString configuratorClassName(
		OptionConverter::getSystemProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATOR_CLASS"),
			log4jConfiguratorClassName));
	return configuratorClassName;
}


const LogString DefaultConfigurator::getConfigurationFileName()
{
	static const LogString LOG4CXX_DEFAULT_CONFIGURATION_KEY(LOG4CXX_STR("LOG4CXX_CONFIGURATION"));
	static const LogString LOG4J_DEFAULT_CONFIGURATION_KEY(LOG4CXX_STR("log4j.configuration"));
	const LogString log4jConfigurationFileName(
		OptionConverter::getSystemProperty(LOG4J_DEFAULT_CONFIGURATION_KEY, LOG4CXX_STR("")));
	const LogString configurationFileName(
		OptionConverter::getSystemProperty(LOG4CXX_DEFAULT_CONFIGURATION_KEY,
			log4jConfigurationFileName));
	return configurationFileName;
}


int DefaultConfigurator::getConfigurationWatchDelay()
{
	static const LogString LOG4CXX_DEFAULT_CONFIGURATION_WATCH_KEY(LOG4CXX_STR("LOG4CXX_CONFIGURATION_WATCH_SECONDS"));
	LogString optionStr = OptionConverter::getSystemProperty(LOG4CXX_DEFAULT_CONFIGURATION_WATCH_KEY, LogString());
	int milliseconds = 0;
	if (!optionStr.empty())
		milliseconds = StringHelper::toInt(optionStr) * MillisecondsPerSecond;
	return milliseconds;
}




