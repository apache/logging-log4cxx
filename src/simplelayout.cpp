/***************************************************************************
                          simplelayout.cpp  -  class SimpleLayout
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

#include <log4cxx/simplelayout.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/level.h>

using namespace log4cxx;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(SimpleLayout)

void SimpleLayout::format(tostream& output,
						  const spi::LoggingEvent& event)
{
	output
		<< event.getLevel().toString()
		<< _T(" - ")
		<< event.getRenderedMessage() 
		<< std::endl;
}
