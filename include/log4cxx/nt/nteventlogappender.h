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
		DECLARE_LOG4CXX_OBJECT(NTEventLogAppender)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(NTEventLogAppender)
			LOG4CXX_CAST_ENTRY_CHAIN(AppenderSkeleton)
		END_LOG4CXX_CAST_MAP()

			NTEventLogAppender();
			NTEventLogAppender(const String& server, const String& log,
				const String& source, LayoutPtr layout);

			virtual ~NTEventLogAppender();

			virtual void activateOptions();
			virtual void close();
			virtual void setOption(const String& option, const String& value);

    		/**
    		* The SocketAppender does not use a layout. Hence, this method
    		* returns <code>false</code>.
    		* */
    		bool requiresLayout()
    			{ return true; }

			void setSource(const String& source)
				{ this->source = source; }
			
			const String& getSource() const
				{ return source; }

			void setLog(const String& log)
				{ this->log = log; }
			
			const String& getLog() const
				{ return log; }

			void setServer(const String& server)
				{ this->server = server; }
			
			const String& getServer() const
				{ return server; }

		protected:
			virtual void append(const spi::LoggingEventPtr& event);
			HKEY regGetKey(const String& subkey, unsigned long *disposition);
			void regSetString(HKEY hkey, const String& name, const String& value);
			void regSetDword(HKEY hkey, const String& name, unsigned long value);
			unsigned short getEventType(const spi::LoggingEventPtr& event);
			unsigned short getEventCategory(const spi::LoggingEventPtr& event);
			/*
			 * Add this source with appropriate configuration keys to the registry.
			 */
			void addRegistryInfo();

			// Data
			String server;
			String log;
			String source;
			HANDLE hEventLog;
			SID * pCurrentUserSID;
		}; // class NTEventLogAppender
    }; // namespace nt
}; // namespace log4cxx

#endif //_LOG4CXX_NT_EVENT_LOG_APPENDER_HEADER_
