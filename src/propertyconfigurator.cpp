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

#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/helpers/properties.h>
#include <fstream>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>
#include <log4cxx/defaultcategoryfactory.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/appender.h>
#include <log4cxx/logger.h>
#include <log4cxx/layout.h>
#include <log4cxx/config/propertysetter.h>
#include <log4cxx/helpers/filewatchdog.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/stringtokenizer.h>
#include <log4cxx/helpers/synchronized.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;
using namespace log4cxx::config;


class PropertyWatchdog  : public FileWatchdog
{
public:
	PropertyWatchdog(const String& filename) : FileWatchdog(filename)
	{
	}

	/**
	Call PropertyConfigurator#doConfigure(const String& configFileName,
	const spi::LoggerRepositoryPtr& hierarchy) with the
	<code>filename</code> to reconfigure log4cxx.
	*/
	void doOnChange()
	{
		PropertyConfigurator().doConfigure(filename,
			LogManager::getLoggerRepository());
	}
};

IMPLEMENT_LOG4CXX_OBJECT(PropertyConfigurator)



PropertyConfigurator::PropertyConfigurator()
: loggerFactory(new DefaultCategoryFactory())
{
}


void PropertyConfigurator::doConfigure(const String& configFileName,
	spi::LoggerRepositoryPtr& hierarchy)
{
	Properties props;

	try
	{
#ifdef LOG4CXX_UNICODE
		std::wifstream istream;
#else
		std::ifstream istream;
#endif
		USES_CONVERSION;
		istream.open(T2A(configFileName.c_str()));
		if (istream.fail())
		{
			LogLog::error(
				_T("Could not read configuration file [") + configFileName + _T("]."));
			LogLog::error(
				_T("Ignoring configuration file [") + configFileName + _T("]."));

			return;
		}

		props.load(istream);
		istream.close();
	}
	catch(Exception& e)
	{
		LogLog::error(
			_T("Could not read configuration file [") + configFileName + _T("]."), e);
		LogLog::error(_T("Ignoring configuration file [") + configFileName + _T("]."));

		return;
	}

	// If we reach here, then the config file is alright.
	doConfigure(props, hierarchy);
}

void PropertyConfigurator::configure(const String& configFilename)
{
	PropertyConfigurator().doConfigure(configFilename, LogManager::getLoggerRepository());
}

void PropertyConfigurator::configure(helpers::Properties& properties)
{
	PropertyConfigurator().doConfigure(properties, LogManager::getLoggerRepository());
}

void PropertyConfigurator::configureAndWatch(const String& configFilename)
{
    configureAndWatch(configFilename, FileWatchdog::DEFAULT_DELAY);
}


void PropertyConfigurator::configureAndWatch(
	const String& configFilename, long delay)
{
    PropertyWatchdog * pdog = new PropertyWatchdog(configFilename);
    pdog->setDelay(delay);
    pdog->start();
}

void PropertyConfigurator::doConfigure(helpers::Properties& properties,
	spi::LoggerRepositoryPtr& hierarchy)
{
        static const String DEBUG_KEY("log4j.debug");
	String value = properties.getProperty(DEBUG_KEY);

	if (!value.empty())
	{
		LogLog::setInternalDebugging(OptionConverter::toBoolean(value, true));
	}

        static const String THRESHOLD_PREFIX("log4j.threshold");
	String thresholdStr =
		OptionConverter::findAndSubst(THRESHOLD_PREFIX, properties);

	if (!thresholdStr.empty())
	{
		hierarchy->setThreshold(OptionConverter::toLevel(thresholdStr, Level::getAll()));
		LogLog::debug(_T("Hierarchy threshold set to [")
			+ hierarchy->getThreshold()->toString() + _T("]."));
	}

	configureRootCategory(properties, hierarchy);
	configureLoggerFactory(properties);
	parseCatsAndRenderers(properties, hierarchy);

	LogLog::debug(_T("Finished configuring."));

	// We don't want to hold references to appenders preventing their
	// destruction.
	registry.clear();
}

void PropertyConfigurator::configureLoggerFactory(helpers::Properties& props)
{
     static const String LOGGER_FACTORY_KEY("log4j.loggerFactory");

	String factoryClassName =
		OptionConverter::findAndSubst(LOGGER_FACTORY_KEY, props);

	if (!factoryClassName.empty())
	{
		LogLog::debug(_T("Setting category factory to [") + factoryClassName + _T("]."));
		loggerFactory =
			OptionConverter::instantiateByClassName(
			factoryClassName, LoggerFactory::getStaticClass(), loggerFactory);
                static const String FACTORY_PREFIX("log4j.factory.");
		PropertySetter::setProperties(loggerFactory, props, FACTORY_PREFIX);
	}
}

void PropertyConfigurator::configureRootCategory(helpers::Properties& props,
			spi::LoggerRepositoryPtr& hierarchy)
{
     static const String ROOT_CATEGORY_PREFIX("log4j.rootCategory");
     static const String ROOT_LOGGER_PREFIX("log4j.rootLogger");



	String effectiveFrefix(ROOT_LOGGER_PREFIX);
	String value = OptionConverter::findAndSubst(ROOT_LOGGER_PREFIX, props);

	if (value.empty())
	{
		value = OptionConverter::findAndSubst(ROOT_CATEGORY_PREFIX, props);
		effectiveFrefix = ROOT_CATEGORY_PREFIX;
	}

	if (value.empty())
	{
		LogLog::debug(_T("Could not find root logger information. Is this OK?"));
	}
	else
	{
		LoggerPtr root = hierarchy->getRootLogger();

		synchronized sync(root->getMutex());
                static const String INTERNAL_ROOT_NAME("root");
		parseCategory(props, root, effectiveFrefix, INTERNAL_ROOT_NAME, value);
	}
}

void PropertyConfigurator::parseCatsAndRenderers(helpers::Properties& props,
			spi::LoggerRepositoryPtr& hierarchy)
{
        static const String CATEGORY_PREFIX("log4j.category.");
        static const String LOGGER_PREFIX("log4j.logger.");

	std::vector<String> names = props.propertyNames();

	std::vector<String>::iterator it = names.begin();
	std::vector<String>::iterator itEnd = names.end();
	while (it != itEnd)
	{
		String key = *it++;

		if (key.find(CATEGORY_PREFIX) == 0 || key.find(LOGGER_PREFIX) == 0)
		{
			String loggerName;

			if (key.find(CATEGORY_PREFIX) == 0)
			{
				loggerName = key.substr(CATEGORY_PREFIX.length());
			}
			else if (key.find(LOGGER_PREFIX) == 0)
			{
				loggerName = key.substr(LOGGER_PREFIX.length());
			}

			String value = OptionConverter::findAndSubst(key, props);
			LoggerPtr logger = hierarchy->getLogger(loggerName, loggerFactory);

			synchronized sync(logger->getMutex());
			parseCategory(props, logger, key, loggerName, value);
			parseAdditivityForLogger(props, logger, loggerName);
		}
	}
}

void PropertyConfigurator::parseAdditivityForLogger(helpers::Properties& props,
	LoggerPtr& cat, const String& loggerName)
{

     static const String ADDITIVITY_PREFIX("log4j.additivity.");



	String value =
		OptionConverter::findAndSubst(ADDITIVITY_PREFIX + loggerName, props);
	LogLog::debug(
		_T("Handling ") + ADDITIVITY_PREFIX + loggerName +
		 _T("=[") + value + _T("]"));

	// touch additivity only if necessary
	if (!value.empty())
	{
		bool additivity = OptionConverter::toBoolean(value, true);
		LogLog::debug(_T("Setting additivity for \"") + loggerName +
			_T("\" to ") + (additivity ? _T("true") : _T("false")));
		cat->setAdditivity(additivity);
	}
}

/**
	This method must work for the root category as well.
*/
void PropertyConfigurator::parseCategory(
	helpers::Properties& props, LoggerPtr& logger, const String& optionKey,
	const String& loggerName, const String& value)
{
	LogLog::debug(
		_T("Parsing for [") + loggerName + _T("] with value=[")
		 + value + _T("]."));

	// We must skip over ',' but not white space
	StringTokenizer st(value, _T(","));

	// If value is not in the form ", appender.." or "", then we should set
	// the level of the logger.
	if (!(value.find(_T(",")) == 0 || value.empty()))
	{
		// just to be on the safe side...
		if (!st.hasMoreTokens())
		{
			return;
		}

		String levelStr = st.nextToken();
		LogLog::debug(_T("Level token is [") + levelStr + _T("]."));

                static const String INHERITED("inherited");
                static const String NuLL("null");

		// If the level value is inherited, set category level value to
		// null. We also check that the user has not specified inherited for the
		// root category.
		if (StringHelper::equalsIgnoreCase(INHERITED, levelStr)
			|| StringHelper::equalsIgnoreCase(NuLL, levelStr))
		{
                        static const String INTERNAL_ROOT_NAME("root");
			if (loggerName == INTERNAL_ROOT_NAME)
			{
				LogLog::warn(_T("The root logger cannot be set to null."));
			}
			else
			{
				logger->setLevel(0);
			}
		}
		else
		{
			logger->setLevel(OptionConverter::toLevel(levelStr, Level::getDebug()));
		}

		LogLog::debug(_T("Category ") + loggerName +
			_T(" set to ") + ((logger->getLevel() != 0 )?
			logger->getLevel()->toString() : _T("null")));
	}

	// Begin by removing all existing appenders.
	logger->removeAllAppenders();

	AppenderPtr appender;
	String appenderName;

	while (st.hasMoreTokens())
	{
		appenderName = StringHelper::trim(st.nextToken());

		if (appenderName.empty() || appenderName == _T(","))
		{
			continue;
		}

		LogLog::debug(_T("Parsing appender named \"")
			+ appenderName + _T("\"."));
		appender = parseAppender(props, appenderName);

		if (appender != 0)
		{
			logger->addAppender(appender);
		}
	}
}

AppenderPtr PropertyConfigurator::parseAppender(
	helpers::Properties& props, const String& appenderName)
{
	AppenderPtr appender = registryGet(appenderName);

	if (appender != 0)
	{
		LogLog::debug(_T("Appender \"") + appenderName +
			_T("\" was already parsed."));

		return appender;
	}

        static const String APPENDER_PREFIX("log4j.appender.");

	// Appender was not previously initialized.
	String prefix = APPENDER_PREFIX + appenderName;
	String layoutPrefix = prefix + _T(".layout");

	appender =
		OptionConverter::instantiateByKey(
		props, prefix, Appender::getStaticClass(), 0);

	if (appender == 0)
	{
		LogLog::error(_T("Could not instantiate appender named \"")
			+ appenderName + _T("\"."));
		return 0;
	}

	appender->setName(appenderName);

	if (appender->instanceof(OptionHandler::getStaticClass()))
	{
		if (appender->requiresLayout())
		{
			LayoutPtr layout =
				OptionConverter::instantiateByKey(
				props, layoutPrefix, Layout::getStaticClass(), 0);

			if (layout != 0)
			{
				appender->setLayout(layout);
				LogLog::debug(_T("Parsing layout options for \"")
					+ appenderName + _T("\"."));

				//configureOptionHandler(layout, layoutPrefix + ".", props);
				PropertySetter::setProperties(layout, props, layoutPrefix + _T("."));
				LogLog::debug(_T("End of parsing for \"")
					+ appenderName + _T("\"."));
			}
		}

		//configureOptionHandler((OptionHandler) appender, prefix + _T("."), props);
		PropertySetter::setProperties(appender, props, prefix + _T("."));
		LogLog::debug(_T("Parsed \"")
			+ appenderName + _T("\" options."));
	}

	registryPut(appender);

	return appender;
}

void PropertyConfigurator::registryPut(const AppenderPtr& appender)
{
	registry[appender->getName()] = appender;
}

AppenderPtr PropertyConfigurator::registryGet(const String& name)
{
	return registry[name];
}
