/***************************************************************************
                          objectimpl.cpp  -  class ObjectImpl
                             -------------------
    begin                : mer avr 16 2003
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
 
#include <log4cxx/config.h>

#ifdef HAVE_MS_THREAD
#include <windows.h>
#endif

#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/criticalsection.h>
#include <log4cxx/helpers/event.h>
#include <log4cxx/helpers/thread.h>

using namespace log4cxx::helpers;

class EventList
{
protected:
	EventList(Event * event)
	: event(event), next(0)
	{
	}
	
public:
	static void removeAll(EventList * list)
	{
		EventList * item = list;
		while (item != 0)
		{
			item = removeHead(item);
		}
	}
	
	static EventList * removeHead(EventList * list)
	{
		EventList * next = list->next;
		delete list;
		return next;
	}
	
	static EventList * append(EventList * list, Event * event)
	{
		if (list == 0)
		{
			return new EventList(event);
		}
		else
		{
			EventList * current = list;
			EventList * next = list->next;
			while (next != 0)
			{
				current = next;
				next = next->next;
			}
			current->next = new EventList(event);
			return list;
		}
	}
	
	Event * event;
	EventList * next;
};

ObjectImpl::ObjectImpl() : ref(0), eventList(0)
{
}

ObjectImpl::~ObjectImpl()
{
}

void ObjectImpl::addRef() const
{
	Thread::InterlockedIncrement(&ref);
}

void ObjectImpl::releaseRef() const
{
	if (Thread::InterlockedDecrement(&ref) == 0)
	{
		delete this;
	}
}

void ObjectImpl::lock() const
{
	cs.lock();
}

void ObjectImpl::unlock() const
{
	cs.unlock();
}

void ObjectImpl::wait() const
{
	if (cs.getOwningThread() != Thread::getCurrentThreadId())
	{
		if (cs.getOwningThread() == 0)
		{
			throw IllegalMonitorStateException(_T("Object not locked"));
		}
		else
		{
			throw IllegalMonitorStateException(_T("Object not locked by this thread"));
		}
	}
	
	Event event(false, false);
	eventList = EventList::append((EventList *)eventList, &event);
	cs.unlock();
	
	try
	{
		event.wait();
	}
	catch(Exception&)
	{
		cs.lock();
		eventList = EventList::removeHead((EventList *)eventList);
		return;
	}
	
	cs.lock();
}

void ObjectImpl::notify() const
{
	if (cs.getOwningThread() != Thread::getCurrentThreadId())
	{
		if (cs.getOwningThread() == 0)
		{
			throw IllegalMonitorStateException(_T("Object not locked"));
		}
		else
		{
			throw IllegalMonitorStateException(_T("Object not locked by this thread"));
		}
	}
	
	if (eventList != 0)
	{
		((EventList *)eventList)->event->set();
		eventList = EventList::removeHead((EventList *)eventList);
	}
}

void ObjectImpl::notifyAll() const
{
	if (cs.getOwningThread() != Thread::getCurrentThreadId())
	{
		if (cs.getOwningThread() == 0)
		{
			throw IllegalMonitorStateException(_T("Object not locked"));
		}
		else
		{
			throw IllegalMonitorStateException(_T("Object not locked by this thread"));
		}
	}
	
	while (eventList != 0)
	{
		((EventList *)eventList)->event->set();
		eventList = EventList::removeHead((EventList *)eventList);
	}
}

