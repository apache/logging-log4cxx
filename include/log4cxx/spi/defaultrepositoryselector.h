/***************************************************************************
       defaultrepositoryselector.h  -  class DefaultRepositorySelector                              
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

#ifndef _LOG4CXX_SPI_DEFAULT_REPOSITORY_SELECTOR_H
#define _LOG4CXX_SPI_DEFAULT_REPOSITORY_SELECTOR_H

#include <log4cxx/spi/repositoryselector.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/spi/loggerrepository.h>

namespace log4cxx
{
	namespace spi
	{
		class LOG4CXX_EXPORT DefaultRepositorySelector :
			public virtual RepositorySelector,
			public virtual helpers::ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(DefaultRepositorySelector)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(RepositorySelector)
			END_LOG4CXX_CAST_MAP()

			DefaultRepositorySelector(const LoggerRepositoryPtr& repository)
			 : repository(repository)
			{
			}
			
			virtual LoggerRepositoryPtr& getLoggerRepository()
			{
				return repository;
			}

		private:
			LoggerRepositoryPtr repository;
		};
	}; // namespace spi
}; // namespace log4cxx

#endif //_LOG4CXX_SPI_DEFAULT_REPOSITORY_SELECTOR_H
