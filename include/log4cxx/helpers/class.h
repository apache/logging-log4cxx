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

		class InstantiationException : public Exception
		{
		public:
			tstring getMessage() { return _T("Abstract class"); }
		};

		class ClassNotFoundException : public Exception
		{
		public:
			tstring getMessage() { return _T("Class not found"); }
		};

		class Class
		{
		public:
			Class(const tstring& name);
			virtual ObjectPtr newInstance() const;
			const tstring& toString() const;
			const tstring& getName() const;
			static const Class& forName(const tstring& className);

		protected:
			static void registerClass(const Class * newClass);
			tstring name;
		};
	}; // namespace log4cxx
}; // namespace helper

#endif //_LOG4CXX_HELPERS_CLASS_H
