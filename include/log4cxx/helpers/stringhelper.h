/***************************************************************************
                          stringhelper.h  -  description
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
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_HELPERS_STRING_HELPER_H
#define _LOG4CXX_HELPERS_STRING_HELPER_H
 
#include <log4cxx/config.h>
#include <log4cxx/helpers/tchar.h>
#include <stdarg.h>

namespace log4cxx
{
    namespace helpers
    {
        class LOG4CXX_EXPORT StringHelper
        {
           public:
            static String toUpperCase(const String& s);
            static String toLowerCase(const String& s);
            static String trim(const String& s);
			static bool equalsIgnoreCase(const String& s1, const String& s2);
  			static bool endsWith(const String& s, const String& suffix);
			static String format(const String& pattern, va_list argList);
        };
    };
};

#endif //_LOG4CXX_HELPERS_STRING_HELPER_H
