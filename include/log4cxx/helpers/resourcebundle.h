/***************************************************************************
                               resourcebundle.h
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
 
#ifndef _LOG4CXX_HELPERS_RESOURCE_BUNDLE_H
#define _LOG4CXX_HELPERS_RESOURCE_BUNDLE_H

#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/locale.h>

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT MissingResourceException : public Exception
		{
		};
		
		class ResourceBundle;
		typedef ObjectPtrT<ResourceBundle> ResourceBundlePtr;
		
		/** 
		Resource bundles contain locale-specific objects
		*/
		class LOG4CXX_EXPORT ResourceBundle : public ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(ResourceBundle)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(ResourceBundle)
			END_LOG4CXX_CAST_MAP()
			
			/**
			Gets a string for the given key from this resource bundle or one of
			its parents. Calling this method is equivalent to calling

			@param key the key for the desired string 
			@return the string for the given key 
			@throw MissingResourceException - if no object for the given key
			can be found
			*/
			virtual String getString(const String& key) const = 0;

			/**
			Gets a resource bundle using the specified base name and locale
			
			@param baseName the base name of the resource bundle, a fully
			qualified class name or property filename
			@locale the locale for which a resource bundle is desired
			*/
			static ResourceBundlePtr getBundle(const String& baseName,
				const Locale& locale);

		protected:
			/*
			Sets the parent bundle of this bundle. The parent bundle is
			searched by #getString when this bundle does not contain a particular
			resource.

			Parameters:
			parent - this bundle's parent bundle.
			*/
			inline void setParent(const ResourceBundlePtr& parent)
				{ this->parent = parent; }

			/**
			The parent bundle of this bundle. 
			
			The parent bundle is searched by #getString when this bundle does
			not contain a particular resource.
			*/
			ResourceBundlePtr parent;
		}; // class ResourceBundle
 	}; // namespace helpers
}; // namespace log4cxx

#endif
 
