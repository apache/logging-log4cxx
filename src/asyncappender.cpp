/***************************************************************************
                          asyncappender.cpp  -  AsyncAppender
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

#include <log4cxx/asyncappender.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/boundedfifo.h>
#include <log4cxx/spi/loggingevent.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(AsyncAppender)

/** The default buffer size is set to 128 events. */
int AsyncAppender::DEFAULT_BUFFER_SIZE = 128;

AsyncAppender::AsyncAppender()
: locationInfo(false), interruptedWarningMessage(false)
{
	bf = new BoundedFIFO(DEFAULT_BUFFER_SIZE);
	
	dispatcher = new Dispatcher(bf, this);
	dispatcher->start();
}

AsyncAppender::~AsyncAppender()
{
	finalize();
}

void AsyncAppender::append(const spi::LoggingEvent& event)
{
	// Set the NDC and thread name for the calling thread as these
	// LoggingEvent fields were not set at event creation time.
	event.getNDC();
	// Get a copy of this thread's MDC.
	event.getMDCCopy();
	
/*	if(locationInfo)
	{
		event.getLocationInformation();
	}*/
	
	synchronized sync(bf);

	while(bf->isFull())
	{
		//LOGLOG_DEBUG(_T("Waiting for free space in buffer, ")
		//	 << bf->length());
		bf->wait();
	}
	
	bf->put(event.copy());
	if(bf->wasEmpty())
	{
		//LogLog::debug(_T("Notifying dispatcher to process events."));
		bf->notify();
	}
}

void AsyncAppender::close()
{
	{
		synchronized sync(this);
		// avoid multiple close, otherwise one gets NullPointerException
		if(closed)
		{
			return;
		}
		
		closed = true;
	}
	
	// The following cannot be synchronized on "this" because the
	// dispatcher synchronizes with "this" in its while loop. If we
	// did synchronize we would systematically get deadlocks when
	// close was called.
	dispatcher->close();
	
	dispatcher->join();
	dispatcher = 0;
	bf = 0;
}

void AsyncAppender::setBufferSize(int size)
{
	bf->resize(size);
}

int AsyncAppender::getBufferSize()
{
	return bf->getMaxSize();
}

Dispatcher::Dispatcher(helpers::BoundedFIFOPtr bf, AsyncAppender * container)
 : bf(bf), container(container), interrupted(false)
{
	// set the dispatcher priority to lowest possible value
	setPriority(Thread::MIN_PRIORITY);
}

void Dispatcher::close()
{
	synchronized sync(bf);

	interrupted = true;
	// We have a waiting dispacther if and only if bf.length is
	// zero.  In that case, we need to give it a death kiss.
	if(bf->length() == 0)
	{
		bf->notify();
	}
}

void Dispatcher::run()
{
	LoggingEvent * event;

	while(true)
	{
		{
			synchronized sync(bf);
			
			if(bf->length() == 0)
			{
				// Exit loop if interrupted but only if
				// the buffer is empty.
				if(interrupted)
				{
					break;
				}
				bf->wait();
			}
			
			event = bf->get();
			if(bf->wasFull())
			{
				bf->notify();
			}
		} // synchronized

		if(event != 0)
		{
			container->appendLoopOnAppenders(*event);
			delete event;
		}
	} // while

	// close and remove all appenders
	container->removeAllAppenders();
}
