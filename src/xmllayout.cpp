/***************************************************************************
                         xmllayout.cpp  -  XMLLayout
                             -------------------
    begin                : dim mai 18 2003
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

#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/transform.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/iso8601dateformat.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::xml;

IMPLEMENT_LOG4CXX_OBJECT(XMLLayout)

String XMLLayout::LOCATION_INFO_OPTION = _T("LocationInfo");

XMLLayout::XMLLayout()
: locationInfo(false)
{
}

void XMLLayout::setOption(const String& option,
	const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOCATION_INFO_OPTION))
	{
		setLocationInfo(OptionConverter::toBoolean(value, false));
	}
}

void XMLLayout::format(ostream& output, const spi::LoggingEventPtr& event)
{
	output << _T("<log4j:event logger=\"");
	output << event->getLoggerName();
	output << _T("\" timestamp=\"");
	output << event->getTimeStamp();
	output << _T("\" level=\"");
	output << event->getLevel()->toString();
	output << _T("\" thread=\"");
	output << event->getThreadId();
	output << _T("\">") << std::endl;

	output << _T("<log4j:message><![CDATA[");
	// Append the rendered message. Also make sure to escape any
	// existing CDATA sections.
	Transform::appendEscapingCDATA(output, event->getRenderedMessage());
	output << _T("]]></log4j:message>") << std::endl;

	const String& ndc = event->getNDC();
	if(ndc.length() != 0)
	{
		output << _T("<log4j:NDC><![CDATA[");
		output << ndc;
		output << _T("]]></log4j:NDC>") << std::endl;
	}

    std::set<String> mdcKeySet = event->getMDCKeySet();

    if(!mdcKeySet.empty())
    {
		/**
		* Normally a sort isn't required, but for Test Case purposes
		* we need to guarantee a particular order.
		*
		* Besides which, from a human readable point of view, the sorting
		* of the keys is kinda nice..
		*/

		output << _T("<log4j:MDC>") << std::endl;
		for (std::set<String>::iterator i = mdcKeySet.begin();
			i != mdcKeySet.end(); i++)
		{
			String key = *i;
			String val = event->getMDC(key);
			output << _T("    <log4j:data ");
			output << _T("name=\"<![CDATA[");
			Transform::appendEscapingCDATA(output, key);
			output << _T("]]>\"");
			output << _T(" ");
			output << _T("value=\"<![CDATA[");
			Transform::appendEscapingCDATA(output, val);
			output << _T("]]>\"/>") << std::endl;
		}
		output << _T("</log4j:MDC>") << std::endl;
    }

	if(locationInfo)
	{
		output << _T("<log4j:locationInfo file=\"");
		USES_CONVERSION;
		output << A2T(event->getFile());
		output << _T("\" line=\"");
		output << event->getLine();
		output << _T("\"/>") << std::endl;
	}

    std::set<String> propertySet = event->getPropertyKeySet();

    if (!propertySet.empty())
	{
		output << _T("<log4j:properties>\n");
		for (std::set<String>::iterator i = propertySet.begin();
			i != propertySet.end(); i++)
		{
			String propName = *i;
			output << _T("<log4j:data name=\"") << propName;
			String propValue = event->getProperty(propName);
			output << _T("\" value=\"") << propValue;
			output << _T("\"/>") << std::endl;
		}
		output << _T("</log4j:properties>") << std::endl;
    }

	output << _T("</log4j:event>") << std::endl;
}
