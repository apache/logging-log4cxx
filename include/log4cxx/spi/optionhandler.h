/***************************************************************************
                          optionhandler.h  -  class OptionHandler
                             -------------------
    begin                : mar avr 15 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mmcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_SPI_OPTION_HANDLER_H
#define _LOG4CXX_SPI_OPTION_HANDLER_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	namespace spi
	{
		class OptionHandler;
		typedef helpers::ObjectPtrT<OptionHandler> OptionHandlerPtr;

		/**
		A string based interface to configure package components.
		*/
		class LOG4CXX_EXPORT OptionHandler : public virtual helpers::Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(OptionHandler)
			virtual ~OptionHandler() {}

			/**
			Activate the options that were previously set with calls to option
			setters.

			<p>This allows to defer activiation of the options until all
			options have been set. This is required for components which have
			related options that remain ambigous until all are set.

			<p>For example, the FileAppender has the {@link
			FileAppender#setFile File} and {@link
			FileAppender#setAppend Append} options both of
			which are ambigous until the other is also set.  */
			virtual void activateOptions() = 0;


			/**
			Set <code>option</code> to <code>value</code>.

			<p>The handling of each option depends on the OptionHandler
			instance. Some options may become active immediately whereas
			other may be activated only when #activateOptions is
			called.
			*/
			virtual void setOption(const String& option, const String& value) = 0;
		
		}; // class OptionConverter
	}; // namespace spi
}; // namespace log4cxx


#endif //_LOG4CXX_SPI_OPTION_HANDLER_H
