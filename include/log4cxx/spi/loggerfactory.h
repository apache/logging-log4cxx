/***************************************************************************
                          loggerfactory.h  -  class LoggerFactory
                             -------------------
    begin                : mer avr 16 2003
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

#ifndef _LOG4CXX_SPI_LOGGERFACTORY_H
#define _LOG4CXX_SPI_LOGGERFACTORY_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/tchar.h>

namespace log4cxx
{
	class Logger;
	typedef helpers::ObjectPtrT<Logger> LoggerPtr;

	namespace spi
	{
		/**
		Implement this interface to create new instances of Logger or
		a sub-class of Logger.
		*/
		class LoggerFactory : public virtual helpers::Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(LoggerFactory)
			virtual ~LoggerFactory() {}
			virtual LoggerPtr makeNewLoggerInstance(const tstring& name) = 0;
		};

		typedef helpers::ObjectPtrT<LoggerFactory> LoggerFactoryPtr;

	}; // namespace spi
}; // namesapce log4cxx

#endif //_LOG4CXX_SPI_LOGGERFACTORY_H
