/***************************************************************************
                          defaultcategoryfactory.h  -
                          class DefaultCategoryFactory
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

#ifndef _LOG4CXX_DEFAULT_CATEGORY_FACTORY_H
#define _LOG4CXX_DEFAULT_CATEGORY_FACTORY_H

#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/helpers/objectimpl.h>

namespace log4cxx
{
	class Logger;
	typedef helpers::ObjectPtr<Logger> LoggerPtr;
	
	class DefaultCategoryFactory :
		public virtual spi::LoggerFactory,
		public virtual helpers::ObjectImpl
	{
	public:
		virtual LoggerPtr makeNewLoggerInstance(const tstring& name);
	};	
}; // namespace log4cxx

#endif //_LOG4CXX_DEFAULT_CATEGORY_FACTORY_H
