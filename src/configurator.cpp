/***************************************************************************
                          onfigurator.cpp  -  class Configurator
                             -------------------
    begin                : 2003/07/24
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

#include <log4cxx/spi/configurator.h>

using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(Configurator);

/**
Special level value signifying inherited behaviour. The current
value of this string constant is <b>inherited</b>. #NuLL
is a synonym.  */
tstring Configurator::INHERITED = _T("inherited");
			
/**
Special level signifying inherited behaviour, same as
#INHERITED. The current value of this string constant is
<b>null</b>. */
tstring Configurator::NuLL = _T("null");
