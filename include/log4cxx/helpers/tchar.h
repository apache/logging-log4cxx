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
#include <cwchar>

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

#ifndef UNICODE
#ifndef WIN32
inline std::ostream& operator<<(const int64_t& ll, std::ostream& os)
{
	char buff[21];
	sprintf(buff, "%lld", ll);
	os << buff;
	return os;
}
#else
inline std::ostream& operator<<(std::ostream& os, const int64_t& ll)
{
	char buff[21];
	sprintf(buff, "%lld", ll);
	os << buff;
	return os;
}
#endif // WIN32
#else
#ifndef WIN32
inline std::wostream& operator<<(const int64_t& ll, std::wostream& os)
{
	wchar_t buff[21];
#ifdef WIN32
	_snwprintf(buff, 20, L"%lld", ll);
#else
	swprintf(buff, 20, L"%lld", ll);
#endif
	os << buff;
	return os;
}
#else

inline std::wostream& operator<<(std::wostream& os, const int64_t& ll)
{
	wchar_t buff[21];
#ifdef WIN32
	_snwprintf(buff, 20, L"%lld", ll);
#else
	swprintf(buff, 20, L"%lld", ll);
#endif
	os << buff;
	return os;
}
#endif // WIN32
#endif // UNICODE


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

#ifndef TCHAR
	typedef wchar_t TCHAR;
#endif
	#define totupper towupper
	#define totlower towlower
	#define tcout std::wcout
	#define tcerr std::wcerr
#ifdef WIN32
	#define tstrncasecmp _wcsnicmp
#else
	#define tstrncasecmp wcsncasecmp
#endif // WIN32

#ifndef T2A
	#define T2A(src) W2A(src)
#endif

#ifndef T2W
	#define T2W(src) src
#endif

#ifndef A2T
	#define A2T(src) A2W(src)
#endif

#ifndef W2T
	#define W2T(src) src
#endif

	#define ttol(s) wcstol(s, 0, 10)
	#define itot _itow
	#define tcscmp wcscmp
#else // Not UNICODE
	#include <ctype.h>

#ifndef _T
	#define _T(x) x
#endif

	typedef char TCHAR;
	#define totupper toupper
	#define totlower tolower
	#define tcout std::cout
	#define tcerr std::cerr
#ifdef WIN32
	#define tstrncasecmp _strnicmp
#else
	#define tstrncasecmp strncasecmp
#endif // WIN32

#ifndef T2A
	#define T2A(src) src
#endif

#ifndef T2W
	#define T2W(src) A2W(src)
#endif

#ifndef A2T
	#define A2T(src) src
#endif

#ifndef W2T
	#define W2T(src) W2A(src)
#endif

	#define ttol atol
	#define itot itoa
	#define tcscmp strcmp
#endif // UNICODE

namespace log4cxx
{
	typedef std::basic_string<TCHAR> String;
	typedef std::basic_ostringstream<TCHAR> StringBuffer;
	typedef std::basic_ostream<TCHAR> ostream;
	typedef std::basic_istream<TCHAR> istream;
};

#endif //_LOG4CXX_HELPERS_TCHAR_H
