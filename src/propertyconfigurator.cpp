/***************************************************************************
              propertyconfigurator.cpp  -  PropertyConfigurator
                             -------------------
    begin                : 06/19/2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

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

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;
using namespace log4cxx::config;

class NoSuchElementException : public Exception
{
public:
	tstring getMessage() { return tstring(); }
};

class StringTokenizer
{
public:
	StringTokenizer(const tstring& str, const tstring& delim)
	: delim(delim)
	{
		this->str = new TCHAR[str.length() + 1];

#ifdef UNICODE
		wcscpy(this->str, str.c_str());
		token = wcstok(this->str, this->delim.c_str());
#else
		strcpy(this->str, str.c_str());
		token = strtok(this->str, this->delim.c_str());
#endif
	}

	~StringTokenizer()
	{
		delete this->str;
	}

	bool hasMoreTokens()
	{
		return (token != 0);
	}

	tstring nextToken()
	{
		if (token == 0)
		{
			throw NoSuchElementException();
		}

		tstring currentToken = token;

#ifdef UNICODE
		token = wcstok(0, delim.c_str());
#else
		token = strtok(0, delim.c_str());
#endif

		return currentToken;
	}

protected:
	TCHAR * str;
	tstring delim;
	TCHAR * token;
};

tstring PropertyConfigurator::CATEGORY_PREFIX = _T("log4j.category.");
tstring PropertyConfigurator::LOGGER_PREFIX = _T("log4j.logger.");
tstring PropertyConfigurator::FACTORY_PREFIX = _T("log4j.factory");
tstring PropertyConfigurator::ADDITIVITY_PREFIX = _T("log4j.additivity.");
tstring PropertyConfigurator::ROOT_CATEGORY_PREFIX = _T("log4j.rootCategory");
tstring PropertyConfigurator::ROOT_LOGGER_PREFIX = _T("log4j.rootLogger");
tstring PropertyConfigurator::APPENDER_PREFIX = _T("log4j.appender.");
tstring PropertyConfigurator::RENDERER_PREFIX = _T("log4j.renderer.");
tstring PropertyConfigurator::THRESHOLD_PREFIX = _T("log4j.threshold");

#define INHERITED _T("inherited")
#define NuLL _T("null")


/* Key for specifying the {@link org.apache.log4j.spi.LoggerFactory
	LoggerFactory}.  Currently set to "<code>log4j.loggerFactory</code>".  */
tstring PropertyConfigurator::LOGGER_FACTORY_KEY = _T("log4j.loggerFactory");
tstring PropertyConfigurator::INTERNAL_ROOT_NAME = _T("root");

PropertyConfigurator::PropertyConfigurator()
: loggerFactory(new DefaultCategoryFactory())
{
}

void PropertyConfigurator::doConfigure(const tstring& configFileName,
	spi::LoggerRepositoryPtr hierarchy)
{
	Properties props;

	try
	{
#ifdef UNICODE
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
			LogLog::error(_T("Ignoring configuration file [") + configFileName + _T("]."));

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

void PropertyConfigurator::configure(const tstring& configFilename)
{
	PropertyConfigurator().doConfigure(configFilename, LogManager::getLoggerRepository());
}

void PropertyConfigurator::configure(helpers::Properties& properties)
{
	PropertyConfigurator().doConfigure(properties, LogManager::getLoggerRepository());
}

void PropertyConfigurator::doConfigure(helpers::Properties& properties,
	spi::LoggerRepositoryPtr hierarchy)
{
	tstring value = properties.getProperty(LogLog::DEBUG_KEY);

	if (!value.empty())
	{
		LogLog::setInternalDebugging(OptionConverter::toBoolean(value, true));
	}

	tstring thresholdStr =
		OptionConverter::findAndSubst(THRESHOLD_PREFIX, properties);

	if (!thresholdStr.empty())
	{
		hierarchy->setThreshold(OptionConverter::toLevel(thresholdStr, Level::ALL));
		LogLog::debug(_T("Hierarchy threshold set to [")
			+ hierarchy->getThreshold().toString() + _T("]."));
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
	tstring factoryClassName =
		OptionConverter::findAndSubst(LOGGER_FACTORY_KEY, props);

	if (!factoryClassName.empty())
	{
		LogLog::debug(_T("Setting category factory to [") + factoryClassName + _T("]."));
		loggerFactory =
			OptionConverter::instantiateByClassName(
			factoryClassName, LoggerFactory::getStaticClass(), loggerFactory);
		PropertySetter::setProperties(loggerFactory, props, FACTORY_PREFIX + _T("."));
	}
}

void PropertyConfigurator::configureRootCategory(helpers::Properties props,
			spi::LoggerRepositoryPtr hierarchy)
{
	tstring effectiveFrefix = ROOT_LOGGER_PREFIX;
	tstring value = OptionConverter::findAndSubst(ROOT_LOGGER_PREFIX, props);

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

		synchronized sync(root);
		parseCategory(props, root, effectiveFrefix, INTERNAL_ROOT_NAME, value);
	}
}

void PropertyConfigurator::parseCatsAndRenderers(helpers::Properties props,
			spi::LoggerRepositoryPtr hierarchy)
{
	std::vector<tstring> names = props.propertyNames();

	std::vector<tstring>::iterator it = names.begin();
	std::vector<tstring>::iterator itEnd = names.end();
	while (it != itEnd)
	{
		tstring key = *it++;

		if (key.find(CATEGORY_PREFIX) == 0 || key.find(LOGGER_PREFIX) == 0)
		{
			tstring loggerName;

			if (key.find(CATEGORY_PREFIX) == 0)
			{
				loggerName = key.substr(CATEGORY_PREFIX.length());
			}
			else if (key.find(LOGGER_PREFIX) == 0)
			{
				loggerName = key.substr(LOGGER_PREFIX.length());
			}

			tstring value = OptionConverter::findAndSubst(key, props);
			LoggerPtr logger = hierarchy->getLogger(loggerName, loggerFactory);

			synchronized sync(logger);
			parseCategory(props, logger, key, loggerName, value);
			parseAdditivityForLogger(props, logger, loggerName);
		}
	}
}

void PropertyConfigurator::parseAdditivityForLogger(helpers::Properties& props,
	LoggerPtr cat, const tstring& loggerName)
{
	tstring value =
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
	helpers::Properties& props, LoggerPtr logger, const tstring& optionKey,
	const tstring& loggerName, const tstring& value)
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

		tstring levelStr = st.nextToken();
		LogLog::debug(_T("Level token is [" + levelStr + "]."));

		// If the level value is inherited, set category level value to
		// null. We also check that the user has not specified inherited for the
		// root category.
		if (StringHelper::equalsIgnoreCase(INHERITED, levelStr)
			|| StringHelper::equalsIgnoreCase(NuLL, levelStr))
		{
			if (loggerName == INTERNAL_ROOT_NAME)
			{
				LogLog::warn(_T("The root logger cannot be set to null."));
			}
			else
			{
				logger->setLevel(Level::OFF);
			}
		}
		else
		{
			logger->setLevel(OptionConverter::toLevel(levelStr, Level::DEBUG));
		}

		LogLog::debug(_T("Category ") + loggerName +
			_T(" set to ") + logger->getLevel().toString());
	}

	// Begin by removing all existing appenders.
	logger->removeAllAppenders();

	AppenderPtr appender;
	tstring appenderName;

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
	helpers::Properties& props, const tstring& appenderName)
{
	AppenderPtr appender = registryGet(appenderName);

	if (appender != 0)
	{
		LogLog::debug(_T("Appender \"") + appenderName +
			_T("\" was already parsed."));

		return appender;
	}

	// Appender was not previously initialized.
	tstring prefix = APPENDER_PREFIX + appenderName;
	tstring layoutPrefix = prefix + _T(".layout");

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
		PropertySetter::setProperties(appender, props, prefix + ".");
		LogLog::debug(_T("Parsed \"")
			+ appenderName + _T("\" options."));
	}

	registryPut(appender);

	return appender;
}

void PropertyConfigurator::registryPut(AppenderPtr appender)
{
	registry[appender->getName()] = appender;
}

AppenderPtr PropertyConfigurator::registryGet(const tstring& name)
{
	return registry[name];
}
