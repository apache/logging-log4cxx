/***************************************************************************
              basicconfigurator.h  -  BasicConfigurator
                             -------------------
    begin                : 06/19/2003
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

#ifndef _LOG4CXX_BASIC_CONFIGURATOR_H
#define _LOG4CXX_BASIC_CONFIGURATOR_H

#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/config.h>
#include <log4cxx/helpers/tchar.h>
#include <log4cxx/spi/configurator.h>
#include <map>

namespace log4cxx
{
	class Appender;
	typedef helpers::ObjectPtrT<Appender> AppenderPtr;

	/**
	Use this class to quickly configure the package.
	<p>For file based configuration see
	PropertyConfigurator. For XML based configuration see
	DOMConfigurator.
	*/
	class BasicConfigurator
	{
	protected:
		BasicConfigurator() {}

	public:
		/**
		Add a ConsoleAppender that uses PatternLayout
		using the PatternLayout#TTCC_CONVERSION_PATTERN and
		prints to <code>stdout</code> to the root logger.*/
		static void configure();

		/**
		Add <code>appender</code> to the root logger.
		@param appender The appender to add to the root logger.
		*/
		static void configure(AppenderPtr appender);

		/**
		Reset the default hierarchy to its defaut. It is equivalent to
		calling
		<code>Logger::getDefaultHierarchy()->resetConfiguration()</code>.
		See Hierarchy#resetConfiguration() for more details.  */
		static void resetConfiguration();
	}; // class BasicConfigurator
}; // namespace log4cxx

#endif //_LOG4CXX_BASIC_CONFIGURATOR_H
