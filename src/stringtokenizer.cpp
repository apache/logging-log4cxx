/***************************************************************************
                          stringtokenizer.cpp  -  class StringTokenizer
                             -------------------
    begin                : 2003/08/02
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

#include <log4cxx/helpers/stringtokenizer.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

StringTokenizer::StringTokenizer(const String& str, const String& delim)
: delim(delim), state(0)
{
	this->str = new TCHAR[str.length() + 1];

#ifdef UNICODE
	wcscpy(this->str, str.c_str());
#ifdef WIN32
	token = wcstok(this->str, this->delim.c_str());
#else
	token = wcstok(this->str, this->delim.c_str(), &state);
#endif
#else
	strcpy(this->str, str.c_str());
	token = strtok(this->str, this->delim.c_str());
#endif
}

StringTokenizer::~StringTokenizer()
{
	delete this->str;
}

bool StringTokenizer::hasMoreTokens() const
{
	return (token != 0);
}

String StringTokenizer::nextToken()
{
	if (token == 0)
	{
		throw NoSuchElementException();
	}

	String currentToken = token;

#ifdef UNICODE
#ifdef WIN32
	token = wcstok(0, delim.c_str());
#else
	token = wcstok(0, delim.c_str(), &state);
#endif
#else
	token = strtok(0, delim.c_str());
#endif

	return currentToken;
}
