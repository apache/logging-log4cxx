#ifndef _LOG4CXX_PORTABILITY_H
#define _LOG4CXX_PORTABILITY_H

#ifdef _MSC_VER
#include <log4cxx/config_msvc.h>
#else
#include <log4cxx/config_auto_log4cxx.h>
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1200
typedef __int64 apr_int64_t;
#else
typedef long long apr_int64_t;
#endif

typedef apr_int64_t apr_time_t;
typedef int apr_status_t;
struct apr_time_exp_t;
struct apr_pool_t;

#define LOG4CXX_MUTABLE mutable
#define LOG4CXX_ACCESS_MUTABLE(val, C) val

//   alternative definitions for compilers that don't support mutable
//
//#define LOG4CXX_MUTABLE
//#define LOG4CXX_ACCESS_MUTABLE(val, C) (const_cast<C*>(this)->val)

#endif //_LOG4CXX_PORTABILITY_H
