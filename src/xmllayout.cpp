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

tstring XMLLayout::LOCATION_INFO_OPTION = _T("LocationInfo");

XMLLayout::XMLLayout()
: locationInfo(false)
{
}

void XMLLayout::setOption(const tstring& option,
	const tstring& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOCATION_INFO_OPTION))
	{
		setLocationInfo(OptionConverter::toBoolean(value, false));
	}
}

void XMLLayout::format(tostream& output, const spi::LoggingEvent& event)
{
	output << _T("<log4cxx:event logger=\"");
//	output << _T("<event logger=\"");
	output << event.getLoggerName();
	output << _T("\" timestamp=\"");
	ISO8601DateFormat().format(output, event.getTimeStamp());
	output << _T("\" level=\"");
	output << event.getLevel().toString();
	output << _T("\" thread=\"");
	output << event.getThreadId();
	output << _T("\">\r\n");

	output << _T("<log4cxx:message><![CDATA[");
//	output << _T("<message><![CDATA[");
	// Append the rendered message. Also make sure to escape any
	// existing CDATA sections.
	Transform::appendEscapingCDATA(output, event.getRenderedMessage());
	output << _T("]]></log4cxx:message>\r\n");
//	output << _T("]]></message>\r\n");

	const tstring& ndc = event.getNDC();
	if(ndc.length() != 0)
	{
		output << _T("<log4cxx:NDC><![CDATA[");
//		output << _T("<NDC><![CDATA[");
		output << ndc;
		output << _T("]]></log4cxx:NDC>\r\n");
//		output << _T("]]></NDC>\r\n");
	}

	if(locationInfo)
	{
		output << _T("<log4cxx:locationInfo file=\"");
//		output << _T("<locationInfo file=\"");
		USES_CONVERSION;
		output << A2T(event.getFile());
		output << _T("\" line=\"");
		output << event.getLine();
		output << _T("\"/>\r\n");
	}

	output << _T("</log4cxx:event>\r\n\r\n");
//	output << _T("</event>\r\n\r\n");
}
