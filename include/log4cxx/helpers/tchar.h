/***************************************************************************
                          tchar.h 
                             -------------------
    begin                : mar avr 15 2003
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

#ifndef _LOG4CXX_HELPERS_TCHAR_H
#define _LOG4CXX_HELPERS_TCHAR_H

#include <log4cxx/config.h>
#include <string>
#include <iostream>
#include <sstream>

class Convert
{
public:
	static wchar_t * ansiToUnicode(wchar_t * dst, const char * src)
	{
		::mbstowcs(dst, src, 512);
		return dst;
	}

	static char * unicodeToAnsi(char * dst, const wchar_t * src)
	{
		::wcstombs(dst, src, 512);
		return dst;
	}
};

#ifdef WIN32
#ifndef USES_CONVERSION
	#include <malloc.h>
	#define USES_CONVERSION void * _dst = _alloca(1024);
#endif
#else
	#define USES_CONVERSION void * _dst = alloca(1024);
#endif

#ifndef W2A
#define W2A(src) Convert::unicodeToAnsi((char *)_dst, src)
#endif

#ifndef A2W
#define A2W(src) Convert::ansiToUnicode((wchar_t *)_dst, src)
#endif

#ifdef UNICODE
	#include <wctype.h>

#ifndef _T
	#define _T(x) L ## x
#endif

	typedef wchar_t TCHAR;
	typedef std::wstring tstring;
	#define totupper towupper
	#define totlower towlower
	#define tcout std::wcout
	#define tcerr std::wcerr
	/** output stream */
	#define tostream std::wostream
	#define tistream std::wistream
#ifdef WIN32
	#define tstrncasecmp _wcsnicmp
#else
	#define tstrncasecmp wcsncasecmp
#endif // WIN32
	#define T2A(src) W2A(src)

#ifndef T2W
	#define T2W(src) src
#endif

	#define A2T(src) A2W(src)

#ifndef W2T
	#define W2T(src) src
#endif

	#define tostringstream std::wostringstream
	#define ttol(s) wcstol(s, 0, 10)
	#define tcscmp wcscmp
#else // Not UNICODE
	#include <ctype.h>

#ifndef _T
	#define _T(x) x
#endif

	typedef char TCHAR;
	typedef std::string tstring;
	#define totupper toupper
	#define totlower tolower
	#define tcout std::cout
	#define tcerr std::cerr
	/** output stream */
	#define tostream std::ostream
	#define tistream std::istream
#ifdef WIN32
	#define tstrncasecmp _strnicmp
#else
	#define tstrncasecmp strncasecmp
#endif // WIN32
	#define T2A(src) src

#ifndef T2W
	#define T2W(src) A2W(src)
#endif

	#define A2T(src) src

#ifndef W2T
	#define W2T(src) W2A(src)
#endif

	#define tostringstream std::ostringstream
	#define ttol atol
	#define tcscmp strcmp
#endif // UNICODE

#endif //_LOG4CXX_HELPERS_TCHAR_H
