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
void PatternConverter::format(tostream& sbuf, const spi::LoggingEvent& e)
{
	tostringstream os;
	convert(os, e);
	tstring s = os.str();
	
	if(s.empty())
	{
		if(0 < min)
			spacePad(sbuf, min);
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
			spacePad(sbuf, min-len);
		}
		else
		{
			spacePad(sbuf, min-len);
			sbuf << s;
		}
	}
	else
		sbuf << s;
}	

tstring PatternConverter::SPACES[] =
{_T(" "), _T("  "), _T("    "), _T("        "), //1,2,4,8 spaces
_T("                "), // 16 spaces
_T("                                ") }; // 32 spaces

/**
Fast space padding method.
*/
void PatternConverter::spacePad(tostream& sbuf, int length)
{
	while(length >= 32)
	{
		sbuf << SPACES[5];
		length -= 32;
	}
	
	for(int i = 4; i >= 0; i--)
	{	
		if((length & (1<<i)) != 0)
		{
			sbuf << SPACES[i];
		}
	}
}

