/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/logmanager.h>
#include <log4cxx/spi/defaultrepositoryselector.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/spi/rootcategory.h>
#include <log4cxx/spi/loggerfactory.h>
#include <stdexcept>
#include <log4cxx/level.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/loglog.h>
#include <sys/stat.h>

#include <apr_general.h>

#include <log4cxx/spi/loggingevent.h>


using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(DefaultRepositorySelector)

void * LogManager::guard = 0;



RepositorySelectorPtr& LogManager::getRepositorySelector() {
   //
   //     call to initialize APR and trigger "start" of logging clock
   //
   static apr_time_t tm(LoggingEvent::getStartTime());
   static spi::RepositorySelectorPtr selector;
   return selector;
}

void LogManager::setRepositorySelector(spi::RepositorySelectorPtr selector,
	void * guard)
{
	if((LogManager::guard != 0) && (LogManager::guard != guard))
	{
		throw IllegalArgumentException();
	}

	if(selector == 0)
	{
		throw IllegalArgumentException();
	}

	LogManager::guard = guard;
	LogManager::getRepositorySelector() = selector;
}

const String LogManager::getConfiguratorClass() {

   static const String LOG4J_CONFIGURATOR_CLASS_KEY("log4j.configuratorClass");
   static const String LOG4CXX_CONFIGURATOR_CLASS_KEY("LOG4CXX_CONFIGURATOR_CLASS");
   // Use automatic configration to configure the default hierarchy
   const String log4jConfiguratorClassName(
        OptionConverter::getSystemProperty(LOG4J_CONFIGURATOR_CLASS_KEY,_T("")));
   const String configuratorClassName(
        OptionConverter::getSystemProperty(LOG4CXX_CONFIGURATOR_CLASS_KEY,
            log4jConfiguratorClassName));
   return configuratorClassName;
}

const String LogManager::getConfigurationFileName() {
  static const String LOG4CXX_DEFAULT_CONFIGURATION_KEY("LOG4CXX_CONFIGURATION");
  static const String LOG4J_DEFAULT_CONFIGURATION_KEY("log4j.configuration");
  const String log4jConfigurationOptionStr(
          OptionConverter::getSystemProperty(LOG4J_DEFAULT_CONFIGURATION_KEY,_T("")));
  const String configurationOptionStr(
          OptionConverter::getSystemProperty(LOG4CXX_DEFAULT_CONFIGURATION_KEY,
              log4jConfigurationOptionStr));
  return configurationOptionStr;
}


LoggerRepositoryPtr& LogManager::getLoggerRepository()
{
	if (getRepositorySelector() == 0)
	{
		getRepositorySelector() =
			new DefaultRepositorySelector(
				new Hierarchy(
					new RootCategory(Level::getDebug())));

                const String configuratorClassName(getConfiguratorClass());

                String configurationOptionStr(getConfigurationFileName());

		struct stat buff;

		if (configurationOptionStr.empty())
		{
                        configurationOptionStr = "log4cxx.properties";
                        const char* configFilenames[] = {
                             "log4cxx.properties",
                             "log4j.properties",
                             "log4cxx.xml",
                             "log4j.xml",
                             NULL };
                        for (const char** configFile = configFilenames;
                             *configFile != NULL;
                             configFile++) {
                             if (stat(*configFile, &buff) == 0) {
                                configurationOptionStr = *configFile;
                                break;
                             }
                        }
		}

		if (stat(T2A(configurationOptionStr.c_str()), &buff) == 0)
		{
			LogLog::debug(
				_T("Using configuration file [") +configurationOptionStr
				+ _T("] for automatic log4cxx configuration"));

			OptionConverter::selectAndConfigure(
				configurationOptionStr,
				configuratorClassName,
				getRepositorySelector()->getLoggerRepository());
		}
		else
		{
			LogLog::debug(
				_T("Could not find configuration file: [")
				+configurationOptionStr+_T("]."));
		}
	}

	return getRepositorySelector()->getLoggerRepository();
}

LoggerPtr LogManager::getRootLogger()
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	return getLoggerRepository()->getRootLogger();
}

/**
Retrieve the appropriate Logger instance.
*/
LoggerPtr LogManager::getLogger(const String& name)
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	return getLoggerRepository()->getLogger(name);
}

/**
Retrieve the appropriate Logger instance.
*/
LoggerPtr LogManager::getLogger(const String& name,
								spi::LoggerFactoryPtr factory)
{
	// Delegate the actual manufacturing of the logger to the logger repository.
	return getLoggerRepository()->getLogger(name, factory);
}

LoggerPtr LogManager::exists(const String& name)
{
	return getLoggerRepository()->exists(name);
}

LoggerList LogManager::getCurrentLoggers()
{
	return getLoggerRepository()->getCurrentLoggers();
}

void LogManager::shutdown()
{
	getLoggerRepository()->shutdown();
}

void LogManager::resetConfiguration()
{
	getLoggerRepository()->resetConfiguration();
}
