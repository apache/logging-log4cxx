/***************************************************************************
                          defaultcategoryfactory.cpp  -  description
                             -------------------
    begin                : jeu avr 17 2003
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

#include <log4cxx/defaultcategoryfactory.h>
#include <log4cxx/logger.h>

using namespace log4cxx;

IMPLEMENT_LOG4CXX_OBJECT(DefaultCategoryFactory)

LoggerPtr DefaultCategoryFactory::makeNewLoggerInstance(const tstring& name)
{
    return new Logger(name);
}
