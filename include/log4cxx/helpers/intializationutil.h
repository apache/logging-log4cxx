/***************************************************************************
               initializationutil.h  -  class InitializationUtil
                             -------------------
    begin                : 2004/01/04
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/
 
 #include <spi/loggerrepository.h> 
 
namespace log4cxx
{
	namespace helpers
	{
		class InitializationUtil
		{
		public:
			/**
			Configure <code>repository</code> using 
			<code>configuratonResourceStr</code> 
			and <code>configuratorClassNameStr</code>.  
			 
			If <code>configuratonResourceStr</code>  is not a URL it will
			be searched
			as a resource from the classpath. 
			@param repository The repository to configre
			@param configuratonResourceStr URL to the configuration
			resource
			@param configuratorClassNameStr The name of the class to use as
			the configurator. This parameter can be null.
			*/
			static void initialConfiguration(
				spi::LoggerRepositoryPtr repository, 
				const String& configuratonResourceStr,
				const String& configuratorClassNameStr);

		};
	}
}
