/***************************************************************************
                        propertiesresourcebundle.cpp
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

#include <log4cxx/helpers/propertyresourcebundle.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(PropertyResourceBundle)

PropertyResourceBundle::PropertyResourceBundle(istream& inStream)
{
	properties.load(inStream);
}

String PropertyResourceBundle::getString(const String& key) const
{
	String resource;
	PropertyResourceBundlePtr resourceBundle = this;

	do
	{
		resource = resourceBundle->properties.getProperty(key);
		if (!resource.empty())
		{
			return resource;
		}

		resourceBundle = resourceBundle->parent;
	}
	while (resourceBundle != 0);

	throw MissingResourceException();

	return resource;
}
