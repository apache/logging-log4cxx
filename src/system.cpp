/***************************************************************************
                          system.cpp  -  class System
                             -------------------
    begin                : 2003/07/11
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

#include <log4cxx/helpers/system.h>

#if defined(HAVE_FTIME)
#include <sys/timeb.h>
#endif

#if defined(HAVE_GETTIMEOFDAY)
#include <sys/time.h>
#endif

#include <time.h>

using namespace log4cxx::helpers;

long long System::currentTimeMillis()
{
#if defined(HAVE_GETTIMEOFDAY)
    timeval tp;
    ::gettimeofday(&tp, 0);

    return ((long long)tp.tv_sec * 1000LL) + (long long)(tp.tv_usec / 1000);
#elif defined(HAVE_FTIME)
    struct timeb tp;
    ::ftime(&tp);

    return (long long)tp.time + ((long long)tp.millitm * 1000LL);
#else
    return (long long)::time(0) * 1000LL * 1000LL;
#endif
}

tstring System::getProperty(const tstring& key)
{
	USES_CONVERSION;
	return A2T(::getenv(T2A(key.c_str())));
}
