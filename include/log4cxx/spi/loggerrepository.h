/***************************************************************************
                          loggerrepository.h  -  description
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

#ifndef _LOG4CXX_SPI_LOG_REPOSITORY_H
#define _LOG4CXX_SPI_LOG_REPOSITORY_H

#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/tchar.h>
#include <vector>

namespace log4cxx
{
	class Level;

	class Logger;
	typedef helpers::ObjectPtr<Logger> LoggerPtr;

	typedef std::vector<LoggerPtr> LoggerList;
	
	class Appender;
	typedef log4cxx::helpers::ObjectPtr<Appender> AppenderPtr;

	namespace spi
	{
		class HierarchyEventListener;
		typedef log4cxx::helpers::ObjectPtr<HierarchyEventListener>
			HierarchyEventListenerPtr;
			
		class LoggerFactory;
		typedef helpers::ObjectPtr<LoggerFactory> LoggerFactoryPtr;
		
		class LoggerRepository;
		typedef helpers::ObjectPtr<LoggerRepository> LoggerRepositoryPtr;
		
		/**
		A <code>LoggerRepository</code> is used to create and retrieve
        <code>Loggers</code>. The relation between loggers in a repository
        depends on the repository but typically loggers are arranged in a
        named hierarchy.

        <p>In addition to the creational methods, a
        <code>LoggerRepository</code> can be queried for existing loggers,
        can act as a point of registry for events related to loggers.
        */
        class LoggerRepository : public virtual helpers::Object
        {
        public:
			virtual ~LoggerRepository() {}

            /**
            Add a {@link spi::HierarchyEventListener HierarchyEventListener}
			event to the repository.
            */
            virtual void addHierarchyEventListener(HierarchyEventListenerPtr 
				listener) = 0;
            /**
            Is the repository disabled for a given level? The answer depends
            on the repository threshold and the <code>level</code>
            parameter. See also #setThreshold method.  */
            virtual bool isDisabled(int level) = 0;

            /**
            Set the repository-wide threshold. All logging requests below the
            threshold are immediately dropped. By default, the threshold is
            set to <code>Level.ALL</code> which has the lowest possible rank.  */
            virtual void setThreshold(const Level& level) = 0;

            /**
            Another form of {@link #setThreshold(const Level&) 
			setThreshold(Level)} accepting a string
            parameter instead of a <code>Level</code>. */
            virtual void setThreshold(const tstring& val) = 0;

            virtual void emitNoAppenderWarning(LoggerPtr logger) = 0;

            /**
            Get the repository-wide threshold. See {@link
            #setThreshold(const Level&) setThreshold(Level)}
			for an explanation. */
            virtual const Level& getThreshold() = 0;

            virtual LoggerPtr getLogger(const tstring& name) = 0;

            virtual LoggerPtr getLogger(const tstring& name, LoggerFactoryPtr 
				factory) = 0;
				
            virtual LoggerPtr getRootLogger() = 0;

            virtual LoggerPtr exists(const tstring& name) = 0;

            virtual void shutdown() = 0;

            virtual LoggerList getCurrentLoggers() = 0;

            virtual void fireAddAppenderEvent(LoggerPtr logger, AppenderPtr 
				appender) = 0;
				
            virtual void resetConfiguration() = 0;
        }; // class LoggerRepository
	}; // namespace spi
}; // namespace log4cxx

#endif //_LOG4CXX_SPI_LOG_REPOSITORY_H
