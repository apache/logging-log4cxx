/***************************************************************************
                          system.h  -  class System
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

 #ifndef _LOG4CXX_HELPERS_SYSTEM_H
 #define _LOG4CXX_HELPERS_SYSTEM_H

 #include <log4cxx/config.h>
 #include <log4cxx/helpers/tchar.h>

 namespace log4cxx
 {
 	namespace helpers
	{
		class LOG4CXX_EXPORT System
		{
		public:
		/** Returns the current time in milliseconds since midnight (0 hour),
		January 1, 1970.*/
		static int64_t currentTimeMillis();

		/** Gets the system property indicated by the specified key.*/
		static String getProperty(const String& key);
		};
	} // namespace helpers
 }; //  namespace log4cxx

 #endif //_LOG4CXX_HELPERS_SYSTEM_H
