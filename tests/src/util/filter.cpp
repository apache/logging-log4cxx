/***************************************************************************
                            filter.cpp
                             -------------------
    begin                : 2004/01/24
    copyright            : (C) 2004 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include "filter.h"
#include <boost/regex.hpp>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace boost;

String Filter::merge(const String& pattern, const String& in, const String& fmt)
{
	USES_CONVERSION;
	std::string convPattern = T2A(pattern.c_str());
	std::string convIn = T2A(in.c_str());
	std::string convFmt = T2A(fmt.c_str());
	
	std::string result = RegEx(convPattern).Merge(convIn, convFmt);
	return A2T(result.c_str());
	
}

bool Filter::match(const String& pattern, const String& in)
{
	USES_CONVERSION;
	std::string convPattern = T2A(pattern.c_str());
	std::string convIn = T2A(in.c_str());

	return RegEx(convPattern).Match(convIn);
}

