/***************************************************************************
                          writerappender.cpp  -  description
                             -------------------
    begin                : sam avr 19 2003
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

#include <log4cxx/writerappender.h>
#include <log4cxx/helpers/loglog.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

WriterAppender::WriterAppender()
: immediateFlush(true), os(0)
{
}

WriterAppender::WriterAppender(LayoutPtr layout, tostream * os)
: immediateFlush(true), os(os)
{
	this->layout = layout;
}

WriterAppender::~WriterAppender()
{
}

void WriterAppender::append(const spi::LoggingEvent& event)
{

// Reminder: the nesting of calls is:
//
//    doAppend()
//      - check threshold


//      - filter
//      - append();
//        - checkEntryConditions();

//        - subAppend();

	if(!checkEntryConditions())
	{
		return;
	}

	subAppend(event);
}

bool WriterAppender::checkEntryConditions()
{
	if(closed)
	{
		LogLog::warn(_T("Not allowed to write to a closed appender."));
		return false;
	}

	if(os == 0)
	{
		errorHandler->error(
			_T("No output stream or file set for the appender named [")
			+ name+ _T("]."));
		return false;
	}

	if(layout == 0)
	{
		errorHandler->error(
			_T("No layout set for the appender named [")
			+ name+_T("]."));
		return false;
	}

	return true;
}

void WriterAppender::close()
{
	synchronized sync(this);
	
	if(closed)
	{
		return;
	}

	closed = true;
	writeFooter();
	reset();
}

void WriterAppender::subAppend(const spi::LoggingEvent& event)
{
	layout->format(*os, event);

	if(immediateFlush)
	{
		os->flush();
	}
}

void WriterAppender::reset()
{
	closeWriter();
	os = 0;
}

void WriterAppender::writeFooter()
{
	if(layout != 0)
	{
		if(os != 0)
		{
			layout->appendFooter(*os);
			os->flush();
		}
	}
}

void WriterAppender::writeHeader()
{
	if(layout != 0)
	{
		if(os != 0)
		{
			layout->appendHeader(*os);
		}
	}
}
