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
IMPLEMENT_LOG4CXX_OBJECT(Dispatcher)

/** The default buffer size is set to 128 events. */
int AsyncAppender::DEFAULT_BUFFER_SIZE = 128;

AsyncAppender::AsyncAppender()
: locationInfo(false), interruptedWarningMessage(false)
{
	bf = new BoundedFIFO(DEFAULT_BUFFER_SIZE);
	
    aai = new AppenderAttachableImpl();

	dispatcher = new Dispatcher(bf, this);
	dispatcher->start();
}

AsyncAppender::~AsyncAppender()
{
	finalize();
}

void AsyncAppender::addAppender(AppenderPtr newAppender)
{
	synchronized sync(aai);
	aai->addAppender(newAppender);
}

void AsyncAppender::append(const spi::LoggingEventPtr& event)
{
	// Set the NDC and thread name for the calling thread as these
	// LoggingEvent fields were not set at event creation time.
	event->getNDC();
	// Get a copy of this thread's MDC.
	event->getMDCCopy();
	
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

	bf->put(event);
	if(bf->wasEmpty())
	{
		//LOGLOG_DEBUG(_T("Notifying dispatcher to process events."));
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

AppenderList AsyncAppender::getAllAppenders() 
{
	synchronized sync(aai);
	return aai->getAllAppenders();
}

AppenderPtr AsyncAppender::getAppender(const String& name)
{
	synchronized sync(aai);
	return aai->getAppender(name);
}

bool AsyncAppender::isAttached(AppenderPtr appender)
{
	synchronized sync(aai);
	return aai->isAttached(appender);
}

void AsyncAppender::setBufferSize(int size)
{
	bf->resize(size);
}

int AsyncAppender::getBufferSize()
{
	return bf->getMaxSize();
}

void AsyncAppender::removeAllAppenders()
{
    synchronized sync(aai);
	aai->removeAllAppenders();
}

void AsyncAppender::removeAppender(AppenderPtr appender)
{
    synchronized sync(aai);
	aai->removeAppender(appender);
}

void AsyncAppender::removeAppender(const String& name)
{
    synchronized sync(aai);
	aai->removeAppender(name);
}

Dispatcher::Dispatcher(helpers::BoundedFIFOPtr bf, AsyncAppender * container)
 : bf(bf), container(container), aai(container->aai), interrupted(false)
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
	LoggingEventPtr event;

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
					//LOGLOG_DEBUG("Exiting.");
					break;
				}
				//LOGLOG_DEBUG("Waiting for new event to dispatch.");
				bf->wait();
			}
			
			event = bf->get();
			if(bf->wasFull())
			{
				//LOGLOG_DEBUG("Notifying AsyncAppender about freed space.");
				bf->notify();
			}
		} // synchronized

		if(aai != 0 && event != 0)
		{
			synchronized sync(aai);
			aai->appendLoopOnAppenders(event);
		}
	} // while

	// close and remove all appenders
	aai->removeAllAppenders();
}
