/***************************************************************************
                          criticalsection.h  -  CriticalSection
                             -------------------
    begin                : lun avr 21 2003
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

#ifndef _LOG4CXX_HELPERS_CRITICAL_SECTION_H
#define _LOG4CXX_HELPERS_CRITICAL_SECTION_H

#include <log4cxx/config.h>

namespace log4cxx
{
	namespace helpers
	{
		class CriticalSection
		{
		public:
			CriticalSection();
			~CriticalSection();
			void lock();
			void unlock();

			void * mutex;
		};

		/** CriticalSection helper class to be used on call stack
		*/
		class WaitAccess
		{
		public:
			/// lock a critical section
			WaitAccess(CriticalSection& cs) : cs(cs)
			{
				cs.lock();
				locked = true;
			}

			/** automatically unlock the critical section
			if unlock has not be called.
			*/
			~WaitAccess()
			{
				if (locked)
				{
					unlock();
				}
			}

			/// unlock the critical section
			void unlock()
			{
				cs.unlock();
				locked = false;
			}

		private:
			/// the CriticalSection to be automatically unlocked
			CriticalSection& cs;
			/// verify the CriticalSection state
			bool locked;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPERS_CRITICAL_SECTION_H
