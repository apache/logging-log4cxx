/***************************************************************************
                          propertysetter.cpp  -  class PropertySetter
                             -------------------
    begin                : 06/25/2003
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

#include <log4cxx/helpers/object.h>
#include <log4cxx/config/propertysetter.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/appender.h>
#include <log4cxx/layout.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::config;

PropertySetter::PropertySetter(helpers::ObjectPtr obj) : obj(obj)
{
}

void PropertySetter::setProperties(helpers::ObjectPtr obj, Properties& properties, const tstring& prefix)
{
	PropertySetter(obj).setProperties(properties, prefix);
}


void PropertySetter::setProperties(helpers::Properties& properties, const tstring& prefix)
{
	int len = prefix.length();

	std::vector<tstring> names = properties.propertyNames();
	std::vector<tstring>::iterator it;

	for (it = names.begin(); it != names.end(); it++)
	{
		tstring key = *it;
		
		// handle only properties that start with the desired frefix.
		if (key.find(prefix) == 0)
		{
			// ignore key if it contains dots after the prefix
			if (key.find(_T('.'), len + 1) != tstring::npos)
			{
				continue;
			}
			
			tstring value = OptionConverter::findAndSubst(key, properties);
			key = key.substr(len);
			if (key == _T("layout")
				&& obj->instanceof(Appender::getStaticClass()))
			{
				continue;
			}        
			setProperty(key, value);
		}
	}
	activate();
}

void PropertySetter::setProperty(const tstring& name, const tstring& value)
{
	if (value.empty())
		return;
	
	if (obj->instanceof(OptionHandler::getStaticClass()))
	{
		LogLog::debug(_T("Setting option name=[") + 
			name + _T("], value=[") + value + _T("]"));
		OptionHandlerPtr(obj)->setOption(name, value);
	}
}

void PropertySetter::activate()
{
	if (obj->instanceof(OptionHandler::getStaticClass()))
	{
		OptionHandlerPtr(obj)->activateOptions();
	}
}
