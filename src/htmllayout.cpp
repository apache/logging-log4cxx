/***************************************************************************
                          htmllayout.cpp  -  HTMLLayout
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

#include <log4cxx/htmllayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/transform.h>
#include <log4cxx/helpers/iso8601dateformat.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

tstring HTMLLayout::TRACE_PREFIX =_T("<br>&nbsp;&nbsp;&nbsp;&nbsp;");
tstring HTMLLayout::LOCATION_INFO_OPTION = _T("LocationInfo");
tstring HTMLLayout::TITLE_OPTION = _T("Title");

HTMLLayout::HTMLLayout()
: locationInfo(false), title(_T("Log4cxx Log Messages"))
{
}

void HTMLLayout::setOption(const tstring& option,
	const tstring& value)
{
	if (StringHelper::equalsIgnoreCase(option, TITLE_OPTION))
	{
		setTitle(value);
	}
	else if (StringHelper::equalsIgnoreCase(option, LOCATION_INFO_OPTION))
	{
		setLocationInfo(OptionConverter::toBoolean(value, false));
	}
}

void HTMLLayout::format(tostream& output, const spi::LoggingEvent& event)
{
	output << std::endl << _T("<tr>") << std::endl;

	output << _T("<td>");
	ISO8601DateFormat().format(output, event.getTimeStamp());
	output << _T("</td>") << std::endl;

	output << _T("<td title=\"") << event.getThreadId() << _T(" thread\">");
	output << event.getThreadId();
	output << _T("</td>") << std::endl;

	output << _T("<td title=\"Level\">");
	if (event.getLevel().equals(Level::DEBUG))
	{
		output << _T("<font color=\"#339933\">");
		output << event.getLevel().toString();
		output << _T("</font>");
	}
	else if(event.getLevel().isGreaterOrEqual(Level::WARN))
	{
		output << _T("<font color=\"#993300\"><strong>");
		output << event.getLevel().toString();
		output << _T("</strong></font>");
	}
	else
	{
		output << event.getLevel().toString();
	}
	
	output << _T("</td>") << std::endl;

	output << _T("<td title=\"") << event.getLoggerName()
		 << _T(" category\">");
	Transform::appendEscapingTags(output, event.getLoggerName());
	output << _T("</td>") << std::endl;

	if(locationInfo)
	{
		USES_CONVERSION;
		output << _T("<td>");
		Transform::appendEscapingTags(output, A2T(event.getFile()));
		output << _T(':');
		output << event.getLine();
		output << _T("</td>") << std::endl;
	}

	output << _T("<td title=\"Message\">");
	Transform::appendEscapingTags(output, event.getRenderedMessage());
	output << _T("</td>")  << std::endl;
	output << _T("</tr>") << std::endl;

	if (event.getNDC().length() != 0)
	{
		output << _T("<tr><td bgcolor=\"#EEEEEE\" ");
		output << _T("style=\"font-size : xx-small;\" colspan=\"6\" ");
		output << _T("title=\"Nested Diagnostic Context\">");
		output << _T("NDC: ");
		Transform::appendEscapingTags(output, event.getNDC());
		output << _T("</td></tr>") << std::endl;
	}
}

void HTMLLayout::appendHeader(tostream& output)
{
	output << _T("<!DOCTYPE HTML PUBLIC ");
	output << _T("\"-//W3C//DTD HTML 4.01 Transitional//EN\" ");
	output << _T("\"http://www.w3.org/TR/html4/loose.dtd\">") << std::endl;
	output << _T("<html>") << std::endl;
	output << _T("<head>") << std::endl;
	output << _T("<title>") << title << _T("</title>") << std::endl;
	output << _T("<style type=\"text/css\">") << std::endl;
	output << _T("<!--") << std::endl;
	output << _T("body, table {font-family: arial,sans-serif; font-size: x-small;}") << std::endl;
	output << _T("th {background: #336699; color: #FFFFFF; text-align: left;}") << std::endl;
	output << _T("-->") << std::endl;
	output << _T("</style>") << std::endl;
	output << _T("</head>") << std::endl;
	output << _T("<body bgcolor=\"#FFFFFF\" topmargin=\"6\" leftmargin=\"6\">") << std::endl;
	output << _T("<hr size=\"1\" noshade>") << std::endl;
	output << _T("Log session start time ");
	ISO8601DateFormat().format(output, time(0));
	output << _T("<br>") << std::endl;
	output << _T("<br>") << std::endl;
	output << _T("<table cellspacing=\"0\" cellpadding=\"4\" border=\"1\" bordercolor=\"#224466\" width=\"100%\">") << std::endl;
	output << _T("<tr>") << std::endl;
	output << _T("<th>Time</th>") << std::endl;
	output << _T("<th>Thread</th>") << std::endl;
	output << _T("<th>Level</th>") << std::endl;
	output << _T("<th>Category</th>") << std::endl;
	if(locationInfo)
	{
		output << _T("<th>File:Line</th>") << std::endl;
	}
	output << _T("<th>Message</th>") << std::endl;
	output << _T("</tr>") << std::endl;
}

void HTMLLayout::appendFooter(tostream& output)
{
	output << _T("</table>") << std::endl;
	output << _T("<br>") << std::endl;
	output << _T("</body></html>");
}
