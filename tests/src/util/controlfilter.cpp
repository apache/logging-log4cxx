/***************************************************************************
                             linenumberfilter.cpp
                             -------------------
    begin                : 2003/12/11
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include "controlfilter.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

ControlFilter::ControlFilter()
{
}

String ControlFilter::filter(const String& in) const throw(UnexpectedFormatException)
{
	int len = allowedPatterns.size();

	for (int i = 0; i < len; i++)
	{
		if (match(allowedPatterns[i], in))
		{
			return in;
		}
	}

	throw UnexpectedFormatException(String(_T("[")) + in + _T("]"));
}

ControlFilter& ControlFilter::operator<<(const String& allowedPattern)
{
	allowedPatterns.push_back(allowedPattern);
	return *this;
}

