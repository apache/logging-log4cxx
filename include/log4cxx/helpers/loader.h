/***************************************************************************
                          loader.h  -  class Loader
                             -------------------
    begin                : jeu avr 17 2003
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

#ifndef _LOG4CXX_HELPERS_LOADER_H
#define _LOG4CXX_HELPERS_LOADER_H

#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/exception.h>

namespace log4cxx
{
	namespace helpers
	{
		class Class;

		class Loader
		{
		public:
			static const Class& Loader::loadClass(const String& clazz);
		};
	}; // namespace helpers
}; // namespace log4cxx
#endif //_LOG4CXX_HELPERS_LOADER_H
