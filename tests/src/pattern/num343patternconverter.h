/***************************************************************************
                          num343patternconverter.h
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

#include <log4cxx/helpers/patternconverter.h>

namespace log4cxx
{
	class Num343PatternConverter : public helpers::PatternConverter
	{
	public:
		void convert(ostream& sbuf, const spi::LoggingEventPtr& event);
	};
};
