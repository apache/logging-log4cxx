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
#include <log4cxx/file.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/aprinitializer.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(DefaultRepositorySelector)

void * LogManager::guard = 0;



RepositorySelectorPtr& LogManager::getRepositorySelector() {
   //
   //     call to initialize APR and trigger "start" of logging clock
   //
   APRInitializer::initialize();
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

const LogString LogManager::getConfiguratorClass() {

   // Use automatic configration to configure the default hierarchy
   const LogString log4jConfiguratorClassName(
        OptionConverter::getSystemProperty(LOG4CXX_STR("log4j.configuratorClass"),LOG4CXX_STR("")));
   const LogString configuratorClassName(
        OptionConverter::getSystemProperty(LOG4CXX_STR("LOG4CXX_CONFIGURATOR_CLASS"),
            log4jConfiguratorClassName));
   return configuratorClassName;
}

const LogString LogManager::getConfigurationFileName() {
  static const LogString LOG4CXX_DEFAULT_CONFIGURATION_KEY(LOG4CXX_STR("LOG4CXX_CONFIGURATION"));
  static const LogString LOG4J_DEFAULT_CONFIGURATION_KEY(LOG4CXX_STR("log4j.configuration"));
  const LogString log4jConfigurationOptionStr(
          OptionConverter::getSystemProperty(LOG4J_DEFAULT_CONFIGURATION_KEY, LOG4CXX_STR("")));
  const LogString configurationOptionStr(
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

                const LogString configuratorClassName(getConfiguratorClass());

                LogString configurationOptionStr(getConfigurationFileName());
                File configuration(configurationOptionStr);

                if (configurationOptionStr.empty())
                {
                        configuration = LOG4CXX_FILE("log4cxx.properties");
                        if (!configuration.exists()) {
                            File tmp = LOG4CXX_FILE("log4cxx.xml");
                            if (tmp.exists()) {
                              configuration = tmp;
                            } else {
                              tmp = LOG4CXX_FILE("log4j.properties");
                              if (tmp.exists()) {
                                configuration = tmp;
                              } else {
                                tmp = LOG4CXX_FILE("log4j.xml");
                                if (tmp.exists()) {
                                  configuration = tmp;
                                }
                              }
                            }
                          }
                }

                if (configuration.exists())
                {
                        LogString msg(LOG4CXX_STR("Using configuration file ["));
                        msg += configuration.getName();
                        msg += LOG4CXX_STR("] for automatic log4cxx configuration");
                        LogLog::debug(msg);

                        OptionConverter::selectAndConfigure(
                                configuration,
                                configuratorClassName,
                                getRepositorySelector()->getLoggerRepository());
                }
                else
                {
                        LogString msg(LOG4CXX_STR("Could not find configuration file: ["));
                        msg += configuration.getName();
                        msg += LOG4CXX_STR("].");
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
LoggerPtr LogManager::getLogger(const LogString& name)
{
        return getLoggerRepository()->getLogger(name);
}

/**
Retrieve the appropriate Logger instance.
*/
LoggerPtr LogManager::getLogger(const LogString& name,
        const spi::LoggerFactoryPtr& factory)
{
        // Delegate the actual manufacturing of the logger to the logger repository.
        return getLoggerRepository()->getLogger(name, factory);
}

LoggerPtr LogManager::exists(const std::string& name)
{
        LOG4CXX_DECODE_CHAR(n, name);
        return getLoggerRepository()->exists(n);
}

LoggerPtr LogManager::exists(const std::wstring& name)
{
        LOG4CXX_DECODE_WCHAR(n, name);
        return getLoggerRepository()->exists(n);
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
