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

PatternConverter::PatternConverter() : minChar(-1), maxChar(0x7FFFFFFF), leftAlign(false)
{
}

PatternConverter::PatternConverter(const FormattingInfo& fi)
{
	minChar = fi.minChar;
	maxChar = fi.maxChar;
	leftAlign = fi.leftAlign;
}

/**
A template method for formatting in a converter specific way.
*/
void PatternConverter::format(ostream& sbuf, const spi::LoggingEventPtr& e) const
{
	if (minChar == -1 && maxChar == 0x7FFFFFFF)
	{
		convert(sbuf, e);
	}
	else
	{
		os.seekp(0);
		convert(os, e);
		String s = os.str();

		if (s.empty())
		{
			if(0 < minChar)
				sbuf << String(minChar, _T(' '));
			return;
		}

		int len = s.size();

		if (len > maxChar)
		{
			sbuf << (s.substr(len-maxChar));
		}
		else if (len < minChar)
		{
			if (leftAlign)
			{
				sbuf << s;
				sbuf << String(minChar-len, _T(' '));
			}
			else
			{
				sbuf << String(minChar-len, _T(' '));
				sbuf << s;
			}
		}
		else
			sbuf << s;
	}
}


