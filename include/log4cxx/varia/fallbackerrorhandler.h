/***************************************************************************
                          fallbackerrorhandler.h
                             -------------------
    begin                : 2004/01/31
    copyright            : (C) 2004 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_VARIA_FALLBACK_ERROR_HANDLER_H
#define _LOG4CXX_VARIA_FALLBACK_ERROR_HANDLER_H

#include <log4cxx/spi/errorhandler.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/appender.h>
#include <log4cxx/logger.h>
#include <vector>

namespace log4cxx
{
	namespace varia
	{
		/**
		The <code>FallbackErrorHandler</code> implements the ErrorHandler
		interface such that a secondary appender may be specified.  This
		secondary appender takes over if the primary appender fails for
		whatever reason.
		
		<p>The error message is printed on <code>System.err</code>, and
		logged in the new secondary appender.
		*/
		class LOG4CXX_EXPORT FallbackErrorHandler : 
			public virtual spi::ErrorHandler,
			public virtual helpers::ObjectImpl
		{
		private:
			AppenderPtr backup;
			AppenderPtr primary;
			std::vector<LoggerPtr> loggers;

		public:
			DECLARE_LOG4CXX_OBJECT(FallbackErrorHandler)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(spi::OptionHandler)
				LOG4CXX_CAST_ENTRY(spi::ErrorHandler)
			END_LOG4CXX_CAST_MAP()

			FallbackErrorHandler();

			/**
			<em>Adds</em> the logger passed as parameter to the list of
			loggers that we need to search for in case of appender failure.
			*/
			void setLogger(const LoggerPtr& logger);


			/**
			No options to activate.
			*/
            void activateOptions();
            void setOption(const String& name, const String& value);


			/**
			Prints the message and the stack trace of the exception on
			<code>System.err</code>.
			*/
			void error(const String& message, helpers::Exception& e,
				int errorCode) const;

			/**
			Prints the message and the stack trace of the exception on
			<code>System.err</code>.
			*/
			void error(const String& message, helpers::Exception& e,
				int errorCode, const spi::LoggingEventPtr& event) const;


			/**
			Print a the error message passed as parameter on
			<code>System.err</code>.  
			*/
			void error(const String& message) const {}

			/**
			Return the backup appender.
			*/
			const AppenderPtr& getBackupAppender() const
				{ return backup; }

			/**
			The appender to which this error handler is attached.
			*/
			void setAppender(const AppenderPtr& primary);

			/**
			Set the backup appender.
			*/
			void setBackupAppender(const AppenderPtr& backup);
  		};
	}; // namespace varia
}; // namespace log4cxx

#endif //_LOG4CXX_VARIA_FALLBACK_ERROR_HANDLER_H
 
