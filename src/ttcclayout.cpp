/***************************************************************************
                          ttcclayout.cpp  -  class TTCCLayout
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

#include <log4cxx/ttcclayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::spi;

TTCCLayout::TTCCLayout()
: threadPrinting(true), categoryPrefixing(true),
contextPrinting(true), filePrinting(false)
{
	setDateFormat(RELATIVE_TIME_DATE_FORMAT);
	activateOptions();
}

TTCCLayout::TTCCLayout(const tstring& dateFormatType)
: threadPrinting(true), categoryPrefixing(true),
contextPrinting(true), filePrinting(false)
{
	setDateFormat(dateFormatType);
	activateOptions();
}

void TTCCLayout::format(tostream& output, const spi::LoggingEvent& event)
{
	formatDate(output, event);

	if(threadPrinting)
	{
		output << _T("[") << event.getThreadId() << _T("] ");
	}
	
	output << event.getLevel().toString() << _T(" ");

	if(categoryPrefixing)
	{
		output << event.getLoggerName() << _T(" ");
	}

	if(contextPrinting)
	{
		tstring ndc = event.getNDC();

		if(!ndc.empty())
		{
			output << ndc << _T(" ");
		}
	}

	output << _T("- ") << event.getRenderedMessage() << std::endl;
}
