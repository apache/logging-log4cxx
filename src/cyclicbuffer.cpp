/***************************************************************************
                          cyclicbuffer.cpp  -  class CyclicBuffer
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

#include <log4cxx/helpers/cyclicbuffer.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;


/**
Instantiate a new CyclicBuffer of at most <code>maxSize</code> events.
The <code>maxSize</code> argument must a positive integer.
@param maxSize The maximum number of elements in the buffer.
*/
CyclicBuffer::CyclicBuffer(int maxSize)
: maxSize(maxSize), first(0), last(0), numElems(0), ea(maxSize)
{
	if(maxSize < 1)
	{
		StringBuffer oss;
		oss << _T("The maxSize argument (") << maxSize
			<< _T(") is not a positive integer.");
		throw new IllegalArgumentException(oss.str());
	}
 }

CyclicBuffer::~CyclicBuffer()
{
}

/**
Add an <code>event</code> as the last event in the buffer.
*/
void CyclicBuffer::add(const spi::LoggingEventPtr& event)
{
	ea[last] = event;
	if(++last == maxSize)
	{
		last = 0;
	}

	if(numElems < maxSize)
	{
		numElems++;
	}
	else if(++first == maxSize)
	{
		first = 0;
	}
 }


/**
Get the <i>i</i>th oldest event currently in the buffer. If
<em>i</em> is outside the range 0 to the number of elements
currently in the buffer, then <code>null</code> is returned.
*/
spi::LoggingEventPtr CyclicBuffer::get(int i)
{
	if(i < 0 || i >= numElems)
		return 0;

	return ea[(first + i) % maxSize];
}

/**
Get the oldest (first) element in the buffer. The oldest element
is removed from the buffer.
*/
spi::LoggingEventPtr CyclicBuffer::get()
{
	LoggingEventPtr r;
	if(numElems > 0)
	{
		numElems--;
		r = ea[first];
		ea[first] = 0;
		if(++first == maxSize)
		{
			first = 0;
		}
	}
	return r;
}
  
/**
Resize the cyclic buffer to <code>newSize</code>.
@throws IllegalArgumentException if <code>newSize</code> is negative.
*/
void CyclicBuffer::resize(int newSize)
{
	if(newSize < 0)
	{
		StringBuffer oss;
		oss << _T("Negative array size [") << newSize
			<< _T("] not allowed.");
		throw new IllegalArgumentException(oss.str());
	}
	if(newSize == numElems)
		return; // nothing to do

	std::vector<LoggingEventPtr> temp(newSize);

	int loopLen = newSize < numElems ? newSize : numElems;
	int i;

	for(i = 0; i < loopLen; i++)
	{
		temp[i] = ea[first];
		ea[i] = 0;
		if(++first == numElems)
		first = 0;
	}

	ea = temp;
	first = 0;
	numElems = loopLen;
	maxSize = newSize;
	if (loopLen == newSize)
	{
		last = 0;
	}
	else
	{
		last = loopLen;
	}
}
