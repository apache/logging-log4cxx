/***************************************************************************
                          boundedfifo.cpp  -  description
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

#include <log4cxx/helpers/boundedfifo.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(BoundedFIFO)

BoundedFIFO::BoundedFIFO(int maxSize)
 : numElements(0), first(0), next(0), maxSize(maxSize)
{
	if(maxSize < 1)
	{
		tostringstream oss;
		oss << _T("The maxSize argument (") << maxSize
			<< _T(") is not a positive integer.");
		throw new IllegalArgumentException(oss.str());
	}
	buf = new LoggingEvent *[maxSize];
}

LoggingEvent * BoundedFIFO::get()
{
	if(numElements == 0)
	{
		return 0;
	}

	LoggingEvent * r = buf[first];
	buf[first] = 0;

	if(++first == maxSize)
	{
		first = 0;
	}
	
	numElements--;
	return r;
}

void BoundedFIFO::put(log4cxx::spi::LoggingEvent * o)
{
	if(numElements != maxSize)
	{
		buf[next] = o;
		if(++next == maxSize)
		{
			next = 0;
		}
		numElements++;
	}
}

void BoundedFIFO::resize(int newSize)
{
	synchronized sync(this);
	
	if(newSize == maxSize)
	{
		return;
	}

	LoggingEvent * * tmp = new LoggingEvent *[newSize];

	// we should not copy beyond the buf array
	int len1 = maxSize - first;

	// we should not copy beyond the tmp array
	len1 = min(len1, newSize);

	// er.. how much do we actually need to copy?
	// We should not copy more than the actual number of elements.
	len1 = min(len1, numElements);

	// Copy from buf starting a first, to tmp, starting at position 0, len1
	memcpy(tmp, buf + first, len1 * sizeof(LoggingEvent *));

	// Are there any uncopied elements and
	// is there still space in the new array?
	int len2 = 0;
	if((len1 < numElements) && (len1 < newSize))
	{
		len2 = numElements - len1;
		len2 = min(len2, newSize - len1);
		memcpy(tmp, buf + len1, len2 * sizeof(LoggingEvent *));
	}

	this->buf = tmp;
	this->maxSize = newSize;
	this->first=0;
	this->numElements = len1+len2;
	this->next = this->numElements;

	// this should never happen, but again, it just might.
	if(this->next == this->maxSize)
	{
		this->next = 0;
	}
}

