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
 #include <log4cxx/helpers/exception.h>

 namespace log4cxx
 {
 	namespace helpers
	{
		class Properties;
		
		/** The System class contains several useful class fields and methods.
		It cannot be instantiated.
		*/
		class LOG4CXX_EXPORT System
		{
		public:
		/** Returns the current time in milliseconds since midnight (0 hour),
		January 1, 1970.
		
		Returns the current time in milliseconds. Note that while the unit of
		time of the return value is a millisecond, the granularity of the value
		depends on the underlying operating system and may be larger. For
		example, many operating systems measure time in units of tens of
		milliseconds.
		
		@return the difference, measured in milliseconds, between the current
		time and midnight, January 1, 1970 UTC.
		*/
		static int64_t currentTimeMillis();

		/** 
		Gets the system property indicated by the specified key.
		
		@param key the name of the system property.
		
		@return the string value of the system property, or the default value if
		there is no property with that key.
		
		@throws IllegalArgumentException if key is empty.
		*/
		static String getProperty(const String& key);
		
		/**
		Sets the system property indicated by the specified key.

		@param key the name of the system property.
		@param value the value of the system property.

		@throws IllegalArgumentException if key is empty.
		*/
		static void setProperty(const String& key, const String& value);
		
		static void setProperties(const Properties& props);
		};
	} // namespace helpers
 }; //  namespace log4cxx

 #endif //_LOG4CXX_HELPERS_SYSTEM_H
