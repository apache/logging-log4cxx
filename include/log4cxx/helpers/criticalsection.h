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

		protected:
			void * mutex;
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif //_LOG4CXX_HELPERS_CRITICAL_SECTION_H
