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

// appenders
#include <log4cxx/consoleappender.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/rollingfileappender.h>
#include <log4cxx/net/socketappender.h>
#include <log4cxx/net/sockethubappender.h>
#include <log4cxx/net/telnetappender.h>
#include <log4cxx/asyncappender.h>
#ifdef WIN32
#include <log4cxx/nt/nteventlogappender.h>
using namespace log4cxx::nt;
#endif // WIN32

// layouts
#include <log4cxx/simplelayout.h>
#include <log4cxx/ttcclayout.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/htmllayout.h>
#include <log4cxx/xml/xmllayout.h>

// logger
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/level.h>

// filter
#include <log4cxx/spi/filter.h>
#include <log4cxx/varia/denyallfilter.h>
#include <log4cxx/varia/levelmatchfilter.h>
#include <log4cxx/varia/levelrangefilter.h>
#include <log4cxx/varia/stringmatchfilter.h>

// helpers
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>

#ifdef WIN32
#include <log4cxx/helpers/msxmlreader.h>
#elif defined(HAVE_LIBXML)
#include <log4cxx/helpers/gnomexmlreader.h>
#endif // WIN32

using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::helpers;
using namespace log4cxx::net;
using namespace log4cxx::varia;
using namespace log4cxx::spi;

#define CONFIGURATION_TAG _T("log4cxx")
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

	return (it == map.end()) ? NULL : it->second;
}

void AppenderMap::put(const tstring& appenderName, AppenderPtr appender)
{
	map.insert(std::map<tstring, AppenderPtr>::value_type(appenderName, appender));
}

void DOMConfigurator::doConfigure(const tstring& URL)
{
	LogLog::debug(_T("DOMConfigurator configuring file ") + URL + _T("..."));
	appenderBag = new AppenderMap();
#ifdef WIN32
	MsXMLReader xmlReader;
	xmlReader.parse(this, URL);
#elif defined(HAVE_LIBXML)
	GnomeXMLReader xmlReader;
	xmlReader.parse(this, URL);
#endif // WIN32

	delete (AppenderMap *)appenderBag;
}

void DOMConfigurator::BuildElement(const tstring& parentTagName, const tstring& tagName)
{
	if (parentTagName == CONFIGURATION_TAG)
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
			currentLogger = Logger::getRootLogger();
			currentAppenderAttachable = currentLogger.p;
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
	if (elementTagName == CONFIGURATION_TAG)
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
			LogManager::getLoggerRepository()->setThreshold(value);
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
		currentOptionHandler = currentAppender;

		if (!currentAppenderName.empty())
		{
			currentAppender->setName(currentAppenderName);
			currentAppenderName = _T("");
		}
	}
}

void DOMConfigurator::BuildLayoutAttribute(const tstring& name, const tstring& value)
{
	if (name == CLASS_ATTR)
	{
		LogLog::debug(_T("Parsing layout of class: \"")+value+_T("\""));	
		
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
		currentLogger == Logger::getLogger(value);
		currentAppenderAttachable = currentLogger.p;

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

			if (currentLogger == Logger::getRootLogger())
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
		currentOptionHandler = filter.p;

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
	LayoutPtr layout;

	if (className == _T("simplelayout"))
	{
		layout = new SimpleLayout();
	}
	else if (className == _T("ttcclayout"))
	{
		layout = new TTCCLayout();
	}
	else if (className == _T("patternlayout"))
	{
		layout = new PatternLayout();
	}
	else if (className == _T("htmllayout"))
	{
		layout = new HTMLLayout();
	}
	else if (className == _T("xmllayout"))
	{
		layout = new XMLLayout();
	}
	else
	{
		LogLog::error(_T("Could not create Layout [") +className+ _T("]."));
	}

	return layout;
}

AppenderPtr DOMConfigurator::BuildAppender(const tstring& className)
{
	AppenderPtr appender;
	
	if (className == _T("consoleappender"))
	{
		appender = new ConsoleAppender();
	}
	else if (className == _T("fileappender"))
	{
		appender = new FileAppender();
	}
	else if (className == _T("rollingfileappender"))
	{
		appender = new RollingFileAppender();
	}
#ifdef WIN32
	else if (className == _T("nteventlogappender"))
	{
		appender = new NTEventLogAppender();
	}
#endif
	else if (className == _T("socketappender"))
	{
		appender = new SocketAppender();
	}
	else if (className == _T("sockethubappender"))
	{
		appender = new SocketHubAppender();
	}
	else if (className == _T("telnetappender"))
	{
		appender = new TelnetAppender();
	}
	else if (className == _T("asyncappender"))
	{
		AsyncAppender * asyncAppender = new AsyncAppender();
		appender = asyncAppender;
		currentAppenderAttachable = asyncAppender;
	}
	else
	{
		LogLog::error(_T("Could not create Appender [") +className+ _T("]."));
	}


	return appender;
}

FilterPtr DOMConfigurator::BuildFilter(const tstring& className)
{
	FilterPtr filter;

	if (className == _T("denyallfilter"))
	{
		filter = new DenyAllFilter();
	}
	else if (className == _T("levelmatchfilter"))
	{
		filter = new LevelMatchFilter();
	}
	else if (className == _T("levelrangefilter"))
	{
		filter = new LevelRangeFilter();
	}
	else if (className == _T("stringmatchfilter"))
	{
		filter = new StringMatchFilter();
	}
	else
	{
		LogLog::error(_T("Could not create Filter [") +className+ _T("]."));
	}

	return filter;
}
