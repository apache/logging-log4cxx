/***************************************************************************
                        		locale.h
                             -------------------
    begin                : 2004/02/15
    copyright            : (C) 2004 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/
 
#ifndef _LOG4CXX_HELPERS_LOCALE_H
#define _LOG4CXX_HELPERS_LOCALE_H

#include <log4cxx/helpers/tchar.h>

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT Locale
		{
		public:
			Locale(const String& language);
			Locale(const String& language, const String& country);
			Locale(const String& language, const String& country, 
				const String& variant);
				
			static const Locale& getDefault();
			static void setDefault(const Locale& newLocale);
			
			const String& getLanguage() const;
			const String& getCountry() const;
			const String& getVariant() const;
			
		protected:
			String language;
			String country;
			String variant;	
		}; // class Locale
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_LOCALE_H
