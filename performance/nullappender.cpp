/***************************************************************************
                          smtpappender.cpp  -  class SMTPAppender
                             -------------------
    begin                : 2003/08/02
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

#include "nullappender.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::performance;


IMPLEMENT_LOG4CXX_OBJECT(NullAppender)

String NullAppender::s;

NullAppender::NullAppender()
{
}

NullAppender::NullAppender(const LayoutPtr& layout)
{
	this->layout = layout;
}

void NullAppender::close()
{
}

void NullAppender::doAppend(const LoggingEventPtr& event)
{
	if (layout != 0)
	{
		StringBuffer sbuf;
		layout->format(sbuf, event);
		s = sbuf.str();
	}
}

void NullAppender::append(const LoggingEventPtr& event)
{
}

/**
This is a bogus appender but it still uses a layout.
*/
bool NullAppender::requiresLayout() const
{
	return true;
}
