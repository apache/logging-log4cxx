/***************************************************************************
                          patternconverter.cpp  -  class PatternConverter
                             -------------------
    begin                : mer avr 30 2003
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

#include <log4cxx/helpers/patternconverter.h>
#include <log4cxx/helpers/formattinginfo.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(PatternConverter)

PatternConverter::PatternConverter() : min(-1), max(0x7FFFFFFF), leftAlign(false)
{
}

PatternConverter::PatternConverter(const FormattingInfo& fi)
{
	min = fi.min;
	max = fi.max;
	leftAlign = fi.leftAlign;
}

/**
A template method for formatting in a converter specific way.
*/
void PatternConverter::format(ostream& sbuf, const spi::LoggingEventPtr& e)
{
	if (min == 0 && max == 0x7FFFFFFF)
	{
		convert(sbuf, e);
	}
	else
	{
		StringBuffer os;
		convert(os, e);
		String s = os.str();

		if(s.empty())
		{
			if(0 < min)
				sbuf << String(min, _T(' '));
			return;
		}

		int len = s.size();

		if(len > max)
		{
			sbuf << (s.substr(len-max));
		}
		else if(len < min)
		{
			if(leftAlign)
			{
				sbuf << s;
				sbuf << String(min-len, _T(' '));
			}
			else
			{
				sbuf << String(min-len, _T(' '));
				sbuf << s;
			}
		}
		else
			sbuf << s;
	}
}


