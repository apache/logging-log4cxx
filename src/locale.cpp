/***************************************************************************
                        		locale.cpp
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
 
#include <log4cxx/helpers/locale.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

Locale defaultLocale(_T(""));

Locale::Locale(const String& language)
 : language(language)
{
}

Locale::Locale(const String& language, const String& country)
 : language(language), country(country)
{
}

Locale::Locale(const String& language, const String& country, 
 	const String& variant)
: language(language), country(country), variant(variant)
{
}

const Locale& Locale::getDefault()
{
	return defaultLocale;
}

void Locale::setDefault(const Locale& newLocale)
{
	defaultLocale = newLocale;
}

const String& Locale::getLanguage() const
{
	return language;
}

const String& Locale::getCountry() const
{
	return country;
}

const String& Locale::getVariant() const
{
	return variant;
}

