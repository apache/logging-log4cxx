/***************************************************************************
                          appenderattachableimpl.h  -  description
                             -------------------
    begin                : mer avr 16 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef _LOG4CXX_HELPERS_APPENDER_ATTACHABLE_IMPL_H
#define _LOG4CXX_HELPERS_APPENDER_ATTACHABLE_IMPL_H

#include <log4cxx/spi/appenderattachable.h>
#include <log4cxx/helpers/objectimpl.h>

namespace log4cxx
{
    namespace spi
    {
        class LoggingEvent;
        typedef helpers::ObjectPtrT<LoggingEvent> LoggingEventPtr;
    }
    
    namespace helpers
    {
		class AppenderAttachableImpl;
		typedef log4cxx::helpers::ObjectPtrT<AppenderAttachableImpl>
			AppenderAttachableImplPtr;
  
		class AppenderAttachableImpl :
			public virtual spi::AppenderAttachable,
			public virtual helpers::ObjectImpl
        {
        protected:
            /** Array of appenders. */
            AppenderList  appenderList;

        public:
			DECLARE_LOG4CXX_OBJECT(AppenderAttachableImpl)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(AppenderAttachableImpl)
				LOG4CXX_CAST_ENTRY(spi::AppenderAttachable)
			END_LOG4CXX_CAST_MAP()

		  // Methods
            /**
             * Add an appender.
             */
            virtual void addAppender(AppenderPtr newAppender);

            /**
             Call the <code>doAppend</code> method on all attached appenders.
            */
            int appendLoopOnAppenders(const spi::LoggingEventPtr& event);

            /**
             * Get all previously added appenders as an Enumeration.
             */
            virtual AppenderList getAllAppenders();

            /**
             * Get an appender by name.
             */
            virtual AppenderPtr getAppender(const String& name);

            /**
             Returns <code>true</code> if the specified appender is in the
             list of attached appenders, <code>false</code> otherwise.
            */
            virtual bool isAttached(AppenderPtr appender);

            /**
             * Remove all previously added appenders.
             */
            virtual void removeAllAppenders();

            /**
             * Remove the appender passed as parameter from the list of appenders.
             */
            virtual void removeAppender(AppenderPtr appender);

            /**
             * Remove the appender with the name passed as parameter from the
             * list of appenders.
             */
            virtual void removeAppender(const String& name);
        };
    };
};

#endif //_LOG4CXX_HELPERS_APPENDER_ATTACHABLE_IMPL_H
