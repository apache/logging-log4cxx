/***************************************************************************
                          repositoryselector.h  -  class RepositorySelector
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

#ifndef _LOG4CXX_SPI_REPOSITORY_SELECTOR_H
#define _LOG4CXX_SPI_REPOSITORY_SELECTOR_H

#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/object.h>

namespace log4cxx
{
	namespace spi
	{
		class LoggerRepository;
		typedef helpers::ObjectPtrT<LoggerRepository> LoggerRepositoryPtr;
		
		class RepositorySelector;
		typedef helpers::ObjectPtrT<RepositorySelector> RepositorySelectorPtr;

       /**
       The <code>LogManager</code> uses one (and only one)
       <code>RepositorySelector</code> implementation to select the
       {@link LoggerRepository LoggerRepository}
	   for a particular application context.

       <p>It is the responsability of the <code>RepositorySelector</code>
       implementation to track the application context. log4cxx makes no
       assumptions about the application context or on its management.

       <p>See also LogManager.
       */
		class LOG4CXX_EXPORT RepositorySelector : public virtual helpers::Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(RepositorySelector)
			virtual ~RepositorySelector() {}
			virtual LoggerRepositoryPtr& getLoggerRepository() = 0;
		};
	}; //namespace spi
}; //namespace log4cxx

#endif //_LOG4CXX_SPI_REPOSITORY_SELECTOR_H
