/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LOG4CXX_PORTABILITY_H
#define _LOG4CXX_PORTABILITY_H

#if defined(LOG4CXX_STATIC)
#define LOG4CXX_EXPORT
#else
#if defined(_WIN32)
#ifdef LOG4CXX
        #define LOG4CXX_EXPORT __declspec(dllexport)
#else
        #define LOG4CXX_EXPORT __declspec(dllimport)
#endif
#else
#define LOG4CXX_EXPORT
#endif
#endif

#if defined(_MSC_VER)
#pragma warning(disable : 4250 4251 4786 4290)

#ifdef LOG4CXX_STATIC
// cf. file msvc/static/static.cpp
#pragma comment(linker, "/include:?ForceSymbolReferences@@YAXXZ")
#endif


#if defined(_MSC_VER) && _MSC_VER >= 1200
typedef __int64 log4cxx_int64_t;
#else
typedef long long log4cxx_int64_t;
#endif

#else
typedef long long log4cxx_int64_t;

#endif


typedef log4cxx_int64_t log4cxx_time_t;
typedef int log4cxx_status_t;

#if defined(_MSC_VER)
#define HAVE_XML 1
#define LOG4CXX_HAVE_XML 1
#endif

#if !defined(__BORLANDC__)
#define LOG4CXX_RETURN_AFTER_THROW
#endif

#if !defined(_WIN32)
#define HAVE_XML 1
#define LOG4CXX_HAVE_XML 1
#define LOG4CXX_HAVE_SYSLOG 1
#endif

#if !defined(LOG4CXX_HAS_STD_WCOUT)
#define LOG4CXX_HAS_STD_WCOUT 1
#endif

#if !defined(LOG4CXX_HAS_STD_WLOCALE)
#define LOG4CXX_HAS_STD_WLOCALE 1
#endif

#endif //_LOG4CXX_PORTABILITY_H
