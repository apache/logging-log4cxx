/***************************************************************************
                        propertiesresourcebundle.h
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
 
#ifndef _LOG4CXX_HELPERS_PROPERTY_RESOURCE_BUNDLE_H
#define _LOG4CXX_HELPERS_PROPERTY_RESOURCE_BUNDLE_H

#include <log4cxx/helpers/resourcebundle.h>
#include <log4cxx/helpers/properties.h>

namespace log4cxx
{
	namespace helpers
	{
		class PropertyResourceBundle;
		typedef ObjectPtrT<PropertyResourceBundle> PropertyResourceBundlePtr;

		/** 
		PropertyResourceBundle is a concrete subclass of ResourceBundle that
		manages resources for a locale using a set of static strings from a
		property file.
		*/
		class LOG4CXX_EXPORT PropertyResourceBundle : public ResourceBundle
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(PropertyResourceBundle)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(PropertyResourceBundle)
				LOG4CXX_CAST_ENTRY_CHAIN(ResourceBundle)
			END_LOG4CXX_CAST_MAP()
			
			/**
			Creates a property resource bundle.
			@param stream property file to read from.
			@throw IOException
			*/
			PropertyResourceBundle(istream& inStream);

			virtual String getString(const String& key) const;
					
		protected:
			Properties properties;
		}; // class PropertyResourceBundle
 	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_PROPERTY_RESOURCE_BUNDLE_H
 
