/***************************************************************************
                             resourcebundle.cpp
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

#include <log4cxx/helpers/resourcebundle.h>
#include <log4cxx/helpers/propertyresourcebundle.h>
#include <log4cxx/helpers/loader.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ResourceBundle)

ResourceBundlePtr ResourceBundle::getBundle(const String& baseName,
	const Locale& locale)
{
	String bundleName;
	istream * bundleStream;
	PropertyResourceBundlePtr resourceBundle, previous;

	std::vector<String> bundlesNames;

	if (!locale.getVariant().empty())
	{
		bundlesNames.push_back(baseName + _T("_") + 
			locale.getLanguage() + _T("_") + 
			locale.getCountry() + _T("_") +
			locale.getVariant());
	}

	if (!locale.getCountry().empty())
	{
		bundlesNames.push_back(baseName + _T("_") + 
				locale.getLanguage() + _T("_") + 
				locale.getCountry());
	}

	if (!locale.getLanguage().empty())
	{
		bundlesNames.push_back(baseName + _T("_") + 
					locale.getLanguage());
	}

	bundlesNames.push_back(baseName);

	for (std::vector<String>::iterator it = bundlesNames.begin();
		it != bundlesNames.end(); it++)
	{
		bundleName = *it;
		
		PropertyResourceBundlePtr current;
		
		try
		{
			const Class& classObj = Loader::loadClass(bundleName);
			current = classObj.newInstance();
		}
		catch(ClassNotFoundException&)
		{
			current = 0;
		}
		
		if (current == 0)
		{
			bundleStream = 
				Loader::getResourceAsStream(bundleName + _T(".properties"));

			if (bundleStream == 0)
			{
				continue;
			}
		}

		try
		{
			current = new PropertyResourceBundle(*bundleStream);
		}
		catch(Exception&)
		{
			delete bundleStream;
			bundleStream = 0;
			throw;
		}
		
		delete bundleStream;
		bundleStream = 0;

		if (resourceBundle == 0)
		{
			resourceBundle = current;
			previous = current;
		}
		else
		{
			previous->setParent(current);
			previous = current;
		}
	}

	if (resourceBundle == 0)
	{
		throw MissingResourceException();
	}

	return resourceBundle;
}


