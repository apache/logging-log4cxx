/***************************************************************************
                          propertysetter.h  -  class PropertySetter
                             -------------------
    begin                : 06/25/2003
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

#ifndef _LOG4CXX_CONFIG_PROPERTYSETTER_H
#define _LOG4CXX_CONFIG_PROPERTYSETTER_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	namespace helpers
	{
		class Object;
		typedef ObjectPtrT<Object> ObjectPtr;

		class Properties;
	};

	namespace config
	{
/**
General purpose Object property setter. Clients repeatedly invokes
{@link #setProperty setProperty(name,value)} in order to invoke setters
on the Object specified in the constructor.

<p>Usage:
<pre>
PropertySetter ps(anObject);
ps.set("name", "Joe");
ps.set("age", "32");
ps.set("isMale", "true");
</pre>
will cause the invocations anObject->setOption("name", "Joe"), 
anObject->setOption("age", "32") and anObject->setOption("isMale", "true")
if the spi::OptionHandler interface is supported by anObject.
*/
		class PropertySetter
		{
		protected: 
			helpers::ObjectPtr obj;
			
		public:
/**
Create a new PropertySetter for the specified Object. This is done
in prepartion for invoking #setProperty one or more times.

@param obj  the object for which to set properties
*/
			PropertySetter(helpers::ObjectPtr obj);
			
/**
Set the properties of an object passed as a parameter in one
go. The <code>properties</code> are parsed relative to a
<code>prefix</code>.

@param obj The object to configure.
@param properties A java.util.Properties containing keys and values.
@param prefix Only keys having the specified prefix will be set.
*/
			static void setProperties(helpers::ObjectPtr obj, helpers::Properties& properties, const tstring& prefix);
			
/**
Set the properites for the object that match the
<code>prefix</code> passed as parameter.
*/
			void setProperties(helpers::Properties& properties, const tstring& prefix);
			
/**
Set a property on this PropertySetter's Object. If the underlying
Object supports the spi::OptionHandler interface, the 
{@link spi::OptionHandler#setOption setOption} method is called.

@param name    name of the property
@param value   tstring value of the property
*/
			void setProperty(const tstring& name, const tstring& value);

			void activate();
		}; // class PropertySetter
	}; // namespace config;
}; // namespace log4cxx

#endif //_LOG4CXX_CONFIG_PROPERTYSETTER_H
