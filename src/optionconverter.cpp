/***************************************************************************
                          optionconverter.cpp  -  class OptionConverter
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

#include <log4cxx/helpers/optionconverter.h>
#include <algorithm>
#include <ctype.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx::helpers;

tstring OptionConverter::DELIM_START = _T("${");
TCHAR OptionConverter::DELIM_STOP  = _T('}');
int OptionConverter::DELIM_START_LEN = 2;
int OptionConverter::DELIM_STOP_LEN  = 1;

namespace {
    // Function object to turn a lower case character into an upper case one
    class ToUpper {
    public:
        void operator()(TCHAR& c){c = toupper(c);}
    };
}

bool OptionConverter::toBoolean(const tstring& value, bool dEfault)
{
	if (value.empty())
	{
		return dEfault;
	}

	tstring trimmedVal = StringHelper::toLowerCase(StringHelper::trim(value));

	if (trimmedVal == _T("true"))
	{
		return true;
	}
	if (trimmedVal == _T("false"))
	{
		return false;
	}

	return dEfault;
}

int OptionConverter::toInt(const tstring& value, int dEfault)
{
	if (value.empty())
	{
		return dEfault;
	}

	return (int)ttol(StringHelper::trim(value).c_str());
}

long OptionConverter::toFileSize(const tstring& value, long dEfault)
{
	if(value.empty())
	{
		return dEfault;
	}

	tstring s = StringHelper::toLowerCase(StringHelper::trim(value));

	long multiplier = 1;
	int index;
	
	if((index = s.find(_T("kb"))) != -1)
	{
		multiplier = 1024;
		s = s.substr(0, index);
	}
	else if((index = s.find(_T("mb"))) != -1) 
	{
		multiplier = 1024*1024;
		s = s.substr(0, index);
	}
	else if((index = s.find(_T("gb"))) != -1)
	{
		multiplier = 1024*1024*1024;
		s = s.substr(0, index);
	}
	if(!s.empty())
	{
		return ttol(s.c_str()) * multiplier;
	}

	return dEfault;
}


