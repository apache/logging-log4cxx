/***************************************************************************
                          appenderattachable.h  -  class AppenderAttachable
                             -------------------
    begin                : mar avr 15 2003
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

#ifndef _LOG4CXX_SPI_APPENDER_ATTACHABLE_H_
#define _LOG4CXX_SPI_APPENDER_ATTACHABLE_H_

#include <log4cxx/helpers/tchar.h>
#include <vector>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/appender.h>

namespace log4cxx
{
    // Forward Declarations
    class Appender;
    typedef helpers::ObjectPtrT<Appender> AppenderPtr;
    typedef std::vector<AppenderPtr> AppenderList;

    namespace spi
    {
		class AppenderAttachable;
		typedef helpers::ObjectPtrT<AppenderAttachable> AppenderAttachablePtr;

        /**
         * This Interface is for attaching Appenders to objects.
         */
        class LOG4CXX_EXPORT AppenderAttachable : public virtual helpers::Object
        {
        public:
          // Methods
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(AppenderAttachable)
            /**
             * Add an appender.
             */
            virtual void addAppender(AppenderPtr newAppender) = 0;

            /**
             * Get all previously added appenders as an AppenderList.
             */
            virtual AppenderList getAllAppenders() = 0;

            /**
             * Get an appender by name.
             */
            virtual AppenderPtr getAppender(const String& name) = 0;

            /**
			Returns <code>true</code> if the specified appender is in list of
			attached attached, <code>false</code> otherwise.
			*/
			virtual bool isAttached(AppenderPtr appender) = 0;

            /**
             * Remove all previously added appenders.
             */
            virtual void removeAllAppenders() = 0;

            /**
             * Remove the appender passed as parameter from the list of appenders.
             */
            virtual void removeAppender(AppenderPtr appender) = 0;

            /**
             * Remove the appender with the name passed as parameter from the
             * list of appenders.
             */
            virtual void removeAppender(const String& name) = 0;

          // Dtor
            virtual ~AppenderAttachable(){}
        };
    };
};

#endif //_LOG4CXX_SPI_APPENDER_ATTACHABLE_H_
