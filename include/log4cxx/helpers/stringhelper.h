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
		/** 
		String manipulation routines
		*/
        class LOG4CXX_EXPORT StringHelper
        {
           public:
            static String toUpperCase(const String& s);
            static String toLowerCase(const String& s);
            static String trim(const String& s);
			static bool equalsIgnoreCase(const String& s1, const String& s2);
  			static bool endsWith(const String& s, const String& suffix);
			/** 
			Creates a message with the given pattern and uses it to format the
			given arguments.
			
			This method provides a means to produce concatenated messages in
			language-neutral way.
			
			@param pattern the pattern for this message. The different arguments
			are represented in the pattern string by the symbols {0} to {9}
			
			@param argList a variable list of srrings to be formatted and
			substituted. The type of the strings must be (TCHAR *).
			*/
			static String format(const String& pattern, va_list argList);
        };
    };
};

#endif //_LOG4CXX_HELPERS_STRING_HELPER_H
