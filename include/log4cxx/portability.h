#ifndef _LOG4CXX_PORTABILITY_H
#define _LOG4CXX_PORTABILITY_H

#if defined(_MSC_VER)
#pragma warning(disable : 4250 4251 4786 4290)

#ifdef LOG4CXX_STATIC
#define LOG4CXX_EXPORT
// cf. file msvc/static/static.cpp
#pragma comment(linker, "/include:?ForceSymbolReferences@@YAXXZ")
#else // DLL
#ifdef LOG4CXX
        #define LOG4CXX_EXPORT __declspec(dllexport)
#else
        #define LOG4CXX_EXPORT __declspec(dllimport)
#endif
#endif


#if defined(_MSC_VER) && _MSC_VER >= 1200
typedef __int64 log4cxx_int64_t;
#else
typedef long long log4cxx_int64_t;
#endif

#else

#define LOG4CXX_EXPORT
typedef long long log4cxx_int64_t;

#endif


typedef log4cxx_int64_t log4cxx_time_t;
typedef int log4cxx_status_t;


#endif //_LOG4CXX_PORTABILITY_H
