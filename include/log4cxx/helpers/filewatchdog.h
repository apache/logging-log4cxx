/***************************************************************************
filewatchdog.h  -  class FileWatchdog
-------------------
begin                : jeu may 15 2003
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

#ifndef _LOG4CXX_HELPERS_FILEWATCHDOG_H
#define _LOG4CXX_HELPERS_FILEWATCHDOG_H

#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/thread.h>
#include <time.h>

namespace log4cxx
{
	namespace helpers
	{
		
		/**
		Check every now and then that a certain file has not changed. If it
		has, then call the #doOnChange method.
		*/
		class LOG4CXX_EXPORT FileWatchdog : public Thread
		{
		public:
			/**
			The default delay between every file modification check, set to 60
			seconds.  */
			static long DEFAULT_DELAY /*= 60000*/; 

		protected:
			/**
			The name of the file to observe  for changes.
			*/
			String filename;
			
			/**
			The delay to observe between every check. 
			By default set DEFAULT_DELAY.*/
			long delay; 
			time_t lastModif; 
			bool warnedAlready;
			bool interrupted;
			
		protected:
			FileWatchdog(const String& filename);
			virtual void doOnChange() = 0;
			void checkAndConfigure();

		public:
			/**
			Set the delay to observe between each check of the file changes.
			*/
			void setDelay(long delay)
				{ this->delay = delay; }
				
			void run();
		};
	}; // namespace helpers
}; // namespace log4cxx


#endif // _LOG4CXX_HELPERS_FILEWATCHDOG_H
