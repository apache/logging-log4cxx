/***************************************************************************
                          num343patternconverter.cpp
                             -------------------
    begin                : 2004/31/01
    copyright            : (C) 2004 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include "num343patternconverter.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

void Num343PatternConverter::convert(ostream& sbuf, const spi::LoggingEventPtr& event)
{
	sbuf << _T("343");
}

