/***************************************************************************
                nteventlogappender.h  -  class NTEventLogAppender
                             -------------------
    begin                : dim avr 20 2003
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

#ifndef _LOG4CXX_NT_EVENT_LOG_APPENDER_HEADER_
#define _LOG4CXX_NT_EVENT_LOG_APPENDER_HEADER_

#include <log4cxx/appenderskeleton.h>

typedef void * HANDLE;
struct HKEY__; 
struct _SID;
typedef struct HKEY__ *HKEY;
typedef struct _SID SID;

namespace log4cxx
{
	namespace nt
	{
		/**
		 * Appends log events to NT EventLog. 
		 */
		class NTEventLogAppender : public AppenderSkeleton
		{
		public:
			NTEventLogAppender();
			NTEventLogAppender(const tstring& server, const tstring& log, const tstring& source, LayoutPtr layout);

			virtual ~NTEventLogAppender();

			virtual void activateOptions();
			virtual void close();
			virtual void setOption(const tstring& option, const tstring& value);

    		/**
    		* The SocketAppender does not use a layout. Hence, this method
    		* returns <code>false</code>.
    		* */
    		bool requiresLayout()
    			{ return true; }

			void setSource(const tstring& source)
				{ this->source = source; }
			
			const tstring& getSource() const
				{ return source; }

			void setLog(const tstring& log)
				{ this->log = log; }
			
			const tstring& getLog() const
				{ return log; }

			void setServer(const tstring& server)
				{ this->server = server; }
			
			const tstring& getServer() const
				{ return server; }

		protected:
			virtual void append(const spi::LoggingEvent& event);
			HKEY regGetKey(const tstring& subkey, unsigned long *disposition);
			void regSetString(HKEY hkey, const tstring& name, const tstring& value);
			void regSetDword(HKEY hkey, const tstring& name, unsigned long value);
			unsigned short getEventType(const spi::LoggingEvent& event);
			unsigned short getEventCategory(const spi::LoggingEvent& event);
			/*
			 * Add this source with appropriate configuration keys to the registry.
			 */
			void addRegistryInfo();

			// Data
			tstring server;
			tstring log;
			tstring source;
			HANDLE hEventLog;
			SID * pCurrentUserSID;
		}; // class NTEventLogAppender
    }; // namespace nt
}; // namespace log4cxx

#endif //_LOG4CXX_NT_EVENT_LOG_APPENDER_HEADER_