/***************************************************************************
                          onlyonceerrorhandler.h  -  description
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

#ifndef _LOG4CXX_HELPERS_ONLY_ONCE_ERROR_HANDLER_H
#define _LOG4CXX_HELPERS_ONLY_ONCE_ERROR_HANDLER_H

#include <log4cxx/spi/errorhandler.h>
#include <log4cxx/helpers/objectimpl.h>

namespace log4cxx
{
	namespace helpers
	{
		/**
		The <code>OnlyOnceErrorHandler</code> implements log4cxx's default
		error handling policy which consists of emitting a message for the
		first error in an appender and ignoring all following errors.

		<p>The error message is printed on <code>System.err</code>.

		<p>This policy aims at protecting an otherwise working application
		from being flooded with error messages when logging fails
		*/
		class LOG4CXX_EXPORT OnlyOnceErrorHandler : 
			public virtual spi::ErrorHandler,
			public virtual ObjectImpl
		{
		private:
			String WARN_PREFIX;
			String ERROR_PREFIX;
			bool firstTime;

		public:
			DECLARE_LOG4CXX_OBJECT(OnlyOnceErrorHandler)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(spi::OptionHandler)
				LOG4CXX_CAST_ENTRY(spi::ErrorHandler)
			END_LOG4CXX_CAST_MAP()

			OnlyOnceErrorHandler();

			/**
			 Does not do anything.
			 */
            void setLogger(const LoggerPtr& logger);


            /**
            No options to activate.
            */
            void activateOptions();
            void setOption(const String& name, const String& value);


            /**
            Prints the message and the stack trace of the exception on
            <code>System.err</code>.  */
            void error(const String& message, Exception& e,
				int errorCode);
            /**
            Prints the message and the stack trace of the exception on
            <code>System.err</code>.
            */
            void error(const String& message, Exception& e,
				int errorCode, const spi::LoggingEventPtr& event);
            
            /**
            Print a the error message passed as parameter on
            <code>System.err</code>.
            */
             void error(const String& message);

            /**
            Does not do anything.
            */
            void setAppender(const AppenderPtr& appender);

            /**
            Does not do anything.
            */
            void setBackupAppender(const AppenderPtr& appender);
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPERS_ONLY_ONCE_ERROR_HANDLER_H
 
