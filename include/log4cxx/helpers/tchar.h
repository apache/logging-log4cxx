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
	#include <malloc.h>
	#define USES_CONVERSION void * _dst = _alloca(1024);
#else
	#define USES_CONVERSION void * _dst = alloca(1024);
#endif
#define W2A(src) Convert::unicodeToAnsi((char *)_dst, src)
#define A2W(src) Convert::ansiToUnicode((wchar_t *)_dst, src)

#ifdef UNICODE
	#include <wctype.h>
	#define _T(x) L ## x
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
	#define T2W(src) src
	#define A2T(src) A2W(src)
	#define W2T(src) src
	#define tostringstream std::wostringstream
	#define ttol(s) wcstol(s, 0, 10)
	#define tcscmp wcscmp
#else // Not UNICODE
	#include <ctype.h>
	#define _T(x) x
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
	#define T2W(src) A2W(src)
	#define A2T(src) src
	#define W2T(src) W2A(src)
	#define tostringstream std::ostringstream
	#define ttol atol
	#define tcscmp strcmp
#endif // UNICODE

#endif //_LOG4CXX_HELPERS_TCHAR_H
