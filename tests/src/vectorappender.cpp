/***************************************************************************
                              vectorappender.cpp
                             -------------------
    begin                : 2003/12/02
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include "vectorappender.h"
#include <log4cxx/helpers/thread.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(VectorAppender)

void VectorAppender::append(const spi::LoggingEventPtr& event)
{
	try
	{
		Thread::sleep(5);
	}
	catch (Exception&)
	{
	}

	vector.push_back(event);
}

void VectorAppender::close()
{
	if (this->closed)
	{
		return;
	}

	this->closed = true;
}
