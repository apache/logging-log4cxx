/***************************************************************************
                          cyclicbuffer.h -  class CyclicBuffer
                             -------------------
    begin                : 2003/07/25
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mmcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#ifndef _LOG4CXX_HELPERS_CYCLICBUFFER_H
#define _LOG4CXX_HELPERS_CYCLICBUFFER_H

#include <log4cxx/spi/loggingevent.h>
#include <vector>

namespace log4cxx
{
	namespace helpers
	{
		/**
		CyclicBuffer is used by other appenders to hold {@link spi::LoggingEvent
		LoggingEvents} for immediate or differed display.
		<p>This buffer gives read access to any element in the buffer not
		just the first or last element.
		*/
		class LOG4CXX_EXPORT CyclicBuffer
		{
			std::vector<spi::LoggingEventPtr> ea;
			int first;
			int last;
			int numElems;
			int maxSize;

		public:
			/**
			Instantiate a new CyclicBuffer of at most <code>maxSize</code>
			events.
			The <code>maxSize</code> argument must a positive integer.
			@param maxSize The maximum number of elements in the buffer.
			@throws IllegalArgumentException if <code>maxSize</code>
			is negative.
			*/
			CyclicBuffer(int maxSize);
			~CyclicBuffer();

			/**
			Add an <code>event</code> as the last event in the buffer.
			*/
			void add(const spi::LoggingEventPtr& event);

			/**
			Get the <i>i</i>th oldest event currently in the buffer. If
			<em>i</em> is outside the range 0 to the number of elements
			currently in the buffer, then <code>null</code> is returned.
			*/
			spi::LoggingEventPtr get(int i);

			int getMaxSize()
				{ return maxSize; }

			/**
			Get the oldest (first) element in the buffer. The oldest element
			is removed from the buffer.
			*/
			spi::LoggingEventPtr get();

			/**
			Get the number of elements in the buffer. This number is
			guaranteed to be in the range 0 to <code>maxSize</code>
			(inclusive).
			*/
			int length()
				{ return numElems; }

			/**
			Resize the cyclic buffer to <code>newSize</code>.
			@throws IllegalArgumentException if <code>newSize</code> is negative.
			*/
			void resize(int newSize);
		}; // class CyclicBuffer
	}; //namespace helpers
}; //namespace log4cxx

#endif //_LOG4CXX_HELPERS_CYCLICBUFFER_H
