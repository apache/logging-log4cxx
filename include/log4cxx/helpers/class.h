/***************************************************************************
                          class.h  -  class Class
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
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_HELPERS_CLASS_H
#define _LOG4CXX_HELPERS_CLASS_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	namespace helpers
	{
		class Object;
		typedef ObjectPtrT<Object> ObjectPtr;

		/**
		Thrown when an application tries to create an instance of a class using
		the newInstance method in class Class, but the specified class object
		cannot be instantiated because it is an interface or is an abstract class.
		*/
		class LOG4CXX_EXPORT InstantiationException : public Exception
		{
		public:
			InstantiationException() : Exception(_T("Abstract class")) {}
		};

		/**
		Thrown when an application tries to load in a class through its
		string name but no definition for the class with the specified name
		could be found.
		*/
		class LOG4CXX_EXPORT ClassNotFoundException : public Exception
		{
		public:
			ClassNotFoundException(const String& className);
		};

		class LOG4CXX_EXPORT Class
		{
		public:
			Class(const String& name);
			virtual ObjectPtr newInstance() const;
			const String& toString() const;
			const String& getName() const;
			static const Class& forName(const String& className);

		protected:
			static void registerClass(const Class * newClass);
			String name;
		};
	}; // namespace log4cxx
}; // namespace helper

#endif //_LOG4CXX_HELPERS_CLASS_H
