/***************************************************************************
                          domconfigurator.cpp  -  DOMConfigurator
                             -------------------
    begin                : dim avr 20 2003
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

#include <log4cxx/config.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/level.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/optionconverter.h>

#ifdef WIN32
#include <log4cxx/helpers/msxmlreader.h>
#elif defined(HAVE_LIBXML)
#include <log4cxx/helpers/gnomexmlreader.h>
#endif // WIN32

using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

#define CONFIGURATION_TAG _T("log4j:configuration")
#define OLD_CONFIGURATION_TAG _T("configuration")
#define APPENDER_TAG _T("appender")
#define APPENDER_REF_TAG _T("appender-ref")
#define PARAM_TAG _T("param")
#define LAYOUT_TAG _T("layout")
#define LOGGER _T("logger")
#define CATEGORY _T("category")
#define NAME_ATTR _T("name")
#define CLASS_ATTR _T("class")
#define VALUE_ATTR _T("value")
#define ROOT_TAG _T("root")
#define ROOT_REF _T("root-ref")
#define LEVEL_TAG _T("level")
#define PRIORITY_TAG _T("priority")
#define FILTER_TAG _T("filter")
#define ERROR_HANDLER_TAG _T("errorHandler")
#define REF_ATTR _T("ref")
#define ADDITIVITY_ATTR _T("additivity")
#define THRESHOLD_ATTR _T("threshold")
#define INTERNAL_DEBUG_ATTR _T("debug")


#define INHERITED _T("inherited")
#define NuLL _T("null")

AppenderPtr AppenderMap::get(const tstring& appenderName)
{
	std::map<tstring, AppenderPtr>::iterator it;
	it = map.find(appenderName);

	return (it == map.end()) ? 0 : it->second;
}

void AppenderMap::put(const tstring& appenderName, AppenderPtr appender)
{
	map.insert(std::map<tstring, AppenderPtr>::value_type(appenderName, appender));
}

void DOMConfigurator::doConfigure(const tstring& filename, spi::LoggerRepositoryPtr repository)
{
	this->repository = repository;
	LogLog::debug(_T("DOMConfigurator configuring file ") + filename + _T("..."));
	appenderBag = new AppenderMap();
#ifdef WIN32
	MsXMLReader xmlReader;
	xmlReader.parse(this, filename);
#elif defined(HAVE_LIBXML)
	GnomeXMLReader xmlReader;
	xmlReader.parse(this, filename);
#endif // WIN32

	delete (AppenderMap *)appenderBag;
}

void DOMConfigurator::configure(const tstring& filename)
{
	DOMConfigurator().doConfigure(filename, LogManager::getLoggerRepository());
}

void DOMConfigurator::BuildElement(const tstring& parentTagName, const tstring& tagName)
{
	if (parentTagName == CONFIGURATION_TAG
		|| parentTagName == OLD_CONFIGURATION_TAG)
	{
		if (currentOptionHandler != 0)
		{
			currentOptionHandler->activateOptions();
			currentOptionHandler = 0;
		}

		if (currentAppenderAttachable != 0)
		{
			currentAppenderAttachable = 0;
		}

		if (currentAppender != 0)
		{
			currentAppender->activateOptions();
			((AppenderMap *)appenderBag)->put(currentAppender->getName(), currentAppender);
			currentAppender = 0;
		}

		if (tagName == ROOT_TAG)
		{
			currentLogger = repository->getRootLogger();
			currentAppenderAttachable = currentLogger;
		}
		else
		{
			currentLogger = 0;
		}
	}
/*
	else if (tagName == ERROR_HANDLER_TAG)
	{
	}*/
}

void DOMConfigurator::BuildAttribute(const tstring& elementTagName, const tstring& name, const tstring& value)
{
	// log4cxx attributes
	if (elementTagName == CONFIGURATION_TAG
		|| elementTagName == OLD_CONFIGURATION_TAG)
	{
		BuildLog4cxxAttribute(StringHelper::toLowerCase(name), value);
	}

	// appender attributes
	else if (elementTagName == APPENDER_TAG)
	{
		BuildAppenderAttribute(StringHelper::toLowerCase(name), value);
	}

	// layout attributes
	else if (elementTagName == LAYOUT_TAG)
	{
		BuildLayoutAttribute(StringHelper::toLowerCase(name), value);
	}

	// parameter attributes
	else if (elementTagName == PARAM_TAG)
	{
		BuildParameterAttribute(StringHelper::toLowerCase(name), value);
	}

	// logger attributes
	else if (elementTagName == LOGGER || elementTagName == CATEGORY)
	{


		BuildLoggerAttribute(StringHelper::toLowerCase(name), value);
	}

	// level attributes
	else if (elementTagName == LEVEL_TAG || elementTagName == PRIORITY_TAG)
	{
		BuildLevelAttribute(StringHelper::toLowerCase(name), value);
	}

	// appender_ref attributes
	else if (elementTagName == APPENDER_REF_TAG)
	{
		BuildAppenderRefAttribute(StringHelper::toLowerCase(name), value);
	}

	// filter attributes
	else if (elementTagName == FILTER_TAG)
	{
		BuildFilterAttribute(StringHelper::toLowerCase(name), value);
	}
}


void DOMConfigurator::BuildLog4cxxAttribute(const tstring& name, const tstring& value)
{
	if (name == INTERNAL_DEBUG_ATTR)
	{
		LogLog::debug(_T("debug attribute= \"") + name +_T("\"."));

		if (!value.empty() || value != _T("null"))
		{
			LogLog::setInternalDebugging(
				OptionConverter::toBoolean(value, true));
		}
		else
		{
			LogLog::debug(tstring(_T("Ignoring ")) + INTERNAL_DEBUG_ATTR + _T(" attribute."));
		}
	}

	if (name == THRESHOLD_ATTR)
	{
		LogLog::debug(_T("Threshold =\"") + value + _T("\"."));

		if (!value.empty() || value != _T("null"))
		{
			repository->setThreshold(value);
		}
	}
}

void DOMConfigurator::BuildAppenderAttribute(const tstring& name, const tstring& value)
{
	if (name == NAME_ATTR)
	{
		if (currentAppender != 0)
		{

			currentAppender->setName(value);
		}
		else
		{
			currentAppenderName = value;
		}
	}
	else if (name == CLASS_ATTR)
	{
		LogLog::debug(_T("Class name: [") + value+_T("]"));

		currentAppender =
			BuildAppender(StringHelper::toLowerCase(value));

		if (currentAppender != 0)
		{
			currentAppenderAttachable = currentAppender;
			currentOptionHandler = currentAppender;

			if (!currentAppenderName.empty())
			{
				currentAppender->setName(currentAppenderName);
				currentAppenderName = _T("");
			}
		}
	}
}

void DOMConfigurator::BuildLayoutAttribute(const tstring& name, const tstring& value)
{
	if (name == CLASS_ATTR)
	{
		LogLog::debug(_T("Parsing layout of class: [")+value+_T("]"));

		LayoutPtr layout = 
			BuildLayout(StringHelper::toLowerCase(value));
		currentOptionHandler = layout;

		if (currentAppender != 0)
		{
			currentAppender->setLayout(layout);
		}
	}
}

void DOMConfigurator::BuildParameterAttribute(const tstring& name, const tstring& value)
{
	if (name == NAME_ATTR)
	{
		currentParamName = value;
	}
	else if (name == VALUE_ATTR)
	{
		currentParamValue = value;
	}

	if (!currentParamName.empty() && !currentParamValue.empty())
	{
		// appender parameter
		if (currentOptionHandler != 0)
		{
			currentOptionHandler->setOption(
				currentParamName,
				currentParamValue);
		}

		currentParamName = _T("");
		currentParamValue = _T("");
	}
}

void DOMConfigurator::BuildLoggerAttribute(const tstring& name, const tstring& value)
{
	if (name == NAME_ATTR)
	{
		LogLog::debug(_T("Retreiving an instance of Logger."));
		currentLogger = repository->getLogger(value);
		currentAppenderAttachable = currentLogger;

		if (!currentAdditivity.empty())
		{
			BuildLoggerAdditivity(currentLogger, currentAdditivity);
			currentAdditivity = _T("");
		}
	}
	else if (name == ADDITIVITY_ATTR)
	{
		if (currentLogger != 0)
		{
			BuildLoggerAdditivity(currentLogger, value);
		}
		else
		{
			currentAdditivity = value;
		}
	}
}

void DOMConfigurator::BuildLevelAttribute(const tstring& name, const tstring& value)
{
	if (name == VALUE_ATTR && currentLogger != 0)
	{
		tstring loggerName = currentLogger->getName();

		LogLog::debug(_T("Level value for ")+loggerName+_T(" is [")+value+_T("]."));

		if (value == INHERITED || value == NuLL)
		{
			// root

			if (currentLogger == repository->getRootLogger())
			{
				LogLog::error(_T("Root level cannot be inherited. Ignoring directive."));
			}
			else
			{

				currentLogger->setLevel(Level::OFF);
			}
		}
		else
		{
			currentLogger->setLevel(Level::toLevel(value, Level::DEBUG));
		}

		LogLog::debug(loggerName + _T(" level set to ") + currentLogger->getLevel().toString());
	}
}

void DOMConfigurator::BuildAppenderRefAttribute(const tstring& name, const tstring& value)
{
	if (name == REF_ATTR && currentAppenderAttachable != 0)
	{
		AppenderPtr appender = ((AppenderMap *)appenderBag)->get(value);

		if (appender != 0)
		{
			if (currentLogger != 0)
			{
				LogLog::debug(_T("Adding appender named [")+ value+ 
					 _T("] to logger [")+currentLogger->getName()+_T("]."));
			}
			else if (currentAppender != 0)
			{
				LogLog::debug(_T("Adding appender named [")+ value+ 
					 _T("] to appender [")+appender->getName()+_T("]."));
			}

			currentAppenderAttachable->addAppender(appender);
		}
		else
		{
			LogLog::error(_T("No appender named [")+value+_T("] could be found."));
		}
	}
}

void DOMConfigurator::BuildFilterAttribute(const tstring& name, const tstring& value)
{
	if (name == CLASS_ATTR && currentAppender != 0)
	{
		FilterPtr filter = BuildFilter(StringHelper::toLowerCase(value));
		currentOptionHandler = filter;

		if (filter != 0)
		{
			LOGLOG_DEBUG(_T("Adding filter of type [") << value
				<< _T("] to appender named [")
				<< currentAppender->getName() << _T("]."));
		   currentAppender->addFilter(filter);
		}
	}
}

void DOMConfigurator::BuildLoggerAdditivity(LoggerPtr& logger, const tstring& additivityValue)
{
	bool additivity = OptionConverter::toBoolean(additivityValue, true);

	LogLog::debug(_T("Setting [")+logger->getName()+
		_T("] additivity to [")+
		(additivity ? _T("true") : _T("false"))+_T("]."));


	currentLogger->setAdditivity(additivity);
}

LayoutPtr DOMConfigurator::BuildLayout(const tstring& className)
{
	LayoutPtr layout = OptionConverter::instantiateByClassName(className,
		Layout::getStaticClass(), 0);
	return layout;
}

AppenderPtr DOMConfigurator::BuildAppender(const tstring& className)
{
	AppenderPtr appender = OptionConverter::instantiateByClassName(className,
		Appender::getStaticClass(), 0);
	return appender;
}

FilterPtr DOMConfigurator::BuildFilter(const tstring& className)
{
	FilterPtr filter = OptionConverter::instantiateByClassName(className,
		Filter::getStaticClass(), 0);
	return filter;
}
