/***************************************************************************
                          threadspecificdata.h  -  class ThreadSpecificData
                             -------------------
    begin                : jeu avr 24 2003
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

#ifndef _LOG4CXX_HELPERS_THREAD_SPECIFIC_DATA_H
#define _LOG4CXX_HELPERS_THREAD_SPECIFIC_DATA_H

#include <log4cxx/config.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT ThreadSpecificData
		{
		public:
			ThreadSpecificData();
			~ThreadSpecificData();
			void * GetData() const;
			void SetData(void * data);

		protected:
#ifdef HAVE_PTHREAD
			pthread_key_t key;
#elif defined(HAVE_MS_THREAD)
			void * key;
#endif
		};
	}; // namespace helpers
}; // namespace log4cxx

#endif
