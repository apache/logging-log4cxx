/***************************************************************************
                          transform.cpp  -  class Transform
                             -------------------
    begin                : sam mai 17 2003
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

#include <log4cxx/helpers/transform.h>

using namespace log4cxx::helpers;

tstring Transform::CDATA_START  = _T("<![CDATA[");
tstring Transform::CDATA_END    = _T("]]>");
tstring Transform::CDATA_PSEUDO_END = _T("]]&gt;");
tstring Transform::CDATA_EMBEDED_END = CDATA_END + CDATA_PSEUDO_END + CDATA_START;
int Transform::CDATA_END_LEN = CDATA_END.length();


void Transform::appendEscapingTags(
	tostream& buf, const tstring& input)
{
	//Check if the string is zero length -- if so, return
	//what was sent in.

	if(input.length() == 0 )
	{
		return;
	}

	tstring::const_iterator it = input.begin();
	tstring::const_iterator itEnd = input.end();
	TCHAR ch;
	while(it != itEnd)
	{
		ch = *it++;
		if(ch == _T('<'))
		{
			buf << _T("&lt;");
		}
		else if(ch == _T('>'))
		{
			buf << _T("&gt;");
		}
		else
		{
			buf.put(ch);
		}
	}
}

void Transform::appendEscapingCDATA(
	tostream& buf, const tstring& input)
{
	if(input.length() == 0 )
	{
		return;
	}

	int end = input.find(CDATA_END);
	if (end == tstring::npos)
	{
		buf << input;
		return;
	}

	int start = 0;
	while (end != tstring::npos)
	{
		buf << input.substr(start, end-start);
		buf << CDATA_EMBEDED_END;
		start = end + CDATA_END_LEN;
		if (start < input.length())
		{
			end = input.find(CDATA_END, start);
		}
		else
		{
			return;
		}
	}

	buf << input.substr(start);
}

