/***************************************************************************
                          hierarchyeventlistener.h  -  description
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

#ifndef _LOG4CXX_SPI_HIERARCHY_EVENT_LISTENER_H
#define _LOG4CXX_SPI_HIERARCHY_EVENT_LISTENER_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/objectptr.h>
#include <vector>

namespace log4cxx
{
	class Logger;
	typedef helpers::ObjectPtrT<Logger> LoggerPtr;
	class Appender;
	typedef helpers::ObjectPtrT<Appender> AppenderPtr;
	
	namespace spi
	{
		class HierarchyEventListener;
		typedef log4cxx::helpers::ObjectPtrT<HierarchyEventListener> 
			HierarchyEventListenerPtr;
		typedef std::vector<HierarchyEventListenerPtr> HierarchyEventListenerList;
			
		/** Listen to events occuring within a Hierarchy.*/
		class LOG4CXX_EXPORT HierarchyEventListener :
			public virtual log4cxx::helpers::Object
		{
		public:
			virtual ~HierarchyEventListener() {}

			virtual void addAppenderEvent(const LoggerPtr& logger, const AppenderPtr& 
				appender) = 0;
				
			virtual void removeAppenderEvent(const LoggerPtr& logger,
				const AppenderPtr& appender) = 0;
		};
	}; // namespace spi
}; // namespace log4cxx

#endif //_LOG4CXX_SPI_HIERARCHY_EVENT_LISTENER_H
