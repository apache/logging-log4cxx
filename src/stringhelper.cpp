/***************************************************************************
                          stringhelper.cpp
                             -------------------
    begin                : 2004/02/14
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
 
#include <log4cxx/helpers/stringhelper.h>
#include <algorithm>
#include <vector>

using namespace log4cxx;
using namespace log4cxx::helpers;

String StringHelper::toUpperCase(const String& s)
{
	String d;
	std::transform(s.begin(), s.end(),
		std::insert_iterator<String>(d, d.begin()), totupper);
	return d;
}

String StringHelper::toLowerCase(const String& s)
{
	String d;
	std::transform(s.begin(), s.end(),
		std::insert_iterator<String>(d, d.begin()), totlower);
	return d;
}

String StringHelper::trim(const String& s)
{
	String::size_type pos = s.find_first_not_of(_T(' '));
	if (pos == String::npos)
	{
		return String();
	}

	String::size_type n = s.find_last_not_of(_T(' ')) - pos + 1;
	return s.substr(pos, n);
}

bool StringHelper::equalsIgnoreCase(const String& s1, const String& s2)
{
	return toLowerCase(s1) == toLowerCase(s2);
}

bool StringHelper::endsWith(const String& s, const String& suffix)
{
	return (s.length() - s.rfind(suffix)) == suffix.length();
}

String StringHelper::format(const String& pattern, va_list argList)
{
	int args = 0;
	const TCHAR * pch = pattern.c_str();	
	while (*pch != _T('\0'))
	{
		if (pch[0] == _T('{') && pch[1] >= _T('0')
			&& pch[1] <= _T('9') && pch[2] == _T('}'))
		{
			int arg = pch[1] - '0' + 1;
			if (arg > args)
			{
				args = arg;
			}
			
			pch += 3;
		}
		else
		{
			++pch;
		}
	}
	
	std::vector<TCHAR *> params(args);
	for (int arg = 0; arg < args; arg++)
	{
		params[arg] = va_arg(argList, TCHAR *);
	}
	
	StringBuffer result;
	
	pch = pattern.c_str();	
	while (*pch != _T('\0'))
	{
		if (pch[0] == _T('{') && pch[1] >= _T('0')
			&& pch[1] <= _T('9') && pch[2] == _T('}'))
		{
			int arg = pch[1] - '0';
			
			result << params[arg];
			pch += 3;
		}
		else
		{
			result.put(*pch);
			++pch;
		}
	}
	
	return result.str();		
}


