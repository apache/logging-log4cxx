/***************************************************************************
                          boundedfifo.h  -  BoundedFIFO
                             -------------------
    begin                : sam mai 17 2003
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

#ifndef _LOG4CXX_HELPERS_BOUNDED_FIFO_H
#define _LOG4CXX_HELPERS_BOUNDED_FIFO_H

#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	namespace spi
	{
		class LoggingEvent;
	};
	
	namespace helpers
	{
		class BoundedFIFO;
		typedef ObjectPtrT<BoundedFIFO> BoundedFIFOPtr;
		
		/**
		<code>BoundedFIFO</code> serves as the bounded first-in-first-out
		buffer heavily used by the AsyncAppender.
		*/
		class BoundedFIFO : public virtual Object, public virtual ObjectImpl
		{
			spi::LoggingEvent * * buf;
			int numElements;
			int first;
			int next;
			int maxSize;

		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(BoundedFIFO)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(BoundedFIFO)
			END_LOG4CXX_CAST_MAP()

			/**
			Instantiate a new BoundedFIFO with a maximum size passed as argument.
			*/
			BoundedFIFO(int maxSize);

			/**
			Get the first element in the buffer. Returns <code>null</code> if
			there are no elements in the buffer.  */
			spi::LoggingEvent * get();

			/**
			Place a {@link spi::LoggingEvent LoggingEvent} in the buffer.
			If the buffer is full
			then the event is <b>silently dropped</b>. It is the caller's
			responsability to make sure that the buffer has free space.  */
			void put(spi::LoggingEvent * o);

			/**
			Get the maximum size of the buffer.
			*/
			inline int getMaxSize() const
				{ return maxSize; }

			/**
			Return <code>true</code> if the buffer is full, i.e. of the
			number of elements in the buffer equals the buffer size. */
			inline bool isFull() const
				{ return numElements == maxSize; }

			/**
			Get the number of elements in the buffer. This number is
			guaranteed to be in the range 0 to <code>maxSize</code>
			(inclusive).
			*/
			inline int length() const
				{ return numElements; }

			/**
			Resize the buffer to a new size. If the new size is smaller than
			the old size events might be lost.
			*/
			void resize(int newSize);
			
			/**
			Returns <code>true</code> if there is just one element in the
			buffer. In other words, if there were no elements before the last
			#put operation completed.  */
			inline bool wasEmpty() const
				{ return numElements == 1; }

			/**
			Returns <code>true</code> if the number of elements in the
			buffer plus 1 equals the maximum buffer size, returns
			<code>false</code> otherwise. */
			inline bool wasFull() const
				{ return (numElements+1 == maxSize); }
				
		}; // class BoundedFIFO
	}; // namespace helpers
}; // namespace log4cxx

#endif // _LOG4CXX_HELPERS_BOUNDED_FIFO_H
