/***************************************************************************
                          configurator.h  -  class Configurator
                             -------------------
    begin                : 2003/07/24
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

#ifndef _LOG4CXX_SPI_CONFIGURATOR_H
#define _LOG4CXX_SPI_CONFIGURATOR_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	namespace spi
	{
		class LoggerRepository;
		typedef helpers::ObjectPtrT<LoggerRepository> LoggerRepositoryPtr;

		class Configurator;
		typedef helpers::ObjectPtrT<Configurator> ConfiguratorPtr;

		/**
		Implemented by classes capable of configuring log4j using a URL.
		*/
		class LOG4CXX_EXPORT Configurator : virtual public helpers::Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(Configurator)
			/**
			Special level value signifying inherited behaviour. The current
			value of this string constant is <b>inherited</b>. #NuLL
			is a synonym.  */
			static String INHERITED /*= "inherited"*/;
			
			/**
			Special level signifying inherited behaviour, same as
			#INHERITED. The current value of this string constant is
			<b>null</b>. */
			static String NuLL /*= "null"*/;
			
			/**
			Interpret a resource pointed by a URL and set up log4j accordingly.

			The configuration is done relative to the <code>hierarchy</code>
			parameter.

			@param configFileName The file to parse
			@param repository The hierarchy to operation upon.
			*/
			virtual void doConfigure(const String& configFileName, 
				spi::LoggerRepositoryPtr& repository) = 0;
		};
	};
};

#endif // _LOG4CXX_SPI_CONFIGURATOR_H
