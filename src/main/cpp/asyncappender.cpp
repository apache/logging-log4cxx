/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined(_MSC_VER)
	#pragma warning ( disable: 4231 4251 4275 4786 )
#endif

#include <log4cxx/asyncappender.h>


#include <log4cxx/helpers/loglog.h>
#include <log4cxx/spi/loggingevent.h>
#include <apr_thread_proc.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <log4cxx/helpers/stringhelper.h>
#include <apr_atomic.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/threadutility.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;


IMPLEMENT_LOG4CXX_OBJECT(AsyncAppender)


AsyncAppender::AsyncAppender()
	: AppenderSkeleton(),
	  buffer(),
	  discardMap(new DiscardMap()),
	  bufferSize(DEFAULT_BUFFER_SIZE),
	  appenders(new AppenderAttachableImpl(pool)),
	  dispatcher(),
	  locationInfo(false),
	  blocking(true)
{
	dispatcher = ThreadUtility::instance()->createThread( LOG4CXX_STR("AsyncAppender"), &AsyncAppender::dispatch, this );
}

AsyncAppender::~AsyncAppender()
{
	finalize();
	delete discardMap;
}

void AsyncAppender::addAppender(const AppenderPtr newAppender)
{
	appenders->addAppender(newAppender);
}


void AsyncAppender::setOption(const LogString& option,
	const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("LOCATIONINFO"), LOG4CXX_STR("locationinfo")))
	{
		setLocationInfo(OptionConverter::toBoolean(value, false));
	}

	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BUFFERSIZE"), LOG4CXX_STR("buffersize")))
	{
		setBufferSize(OptionConverter::toInt(value, DEFAULT_BUFFER_SIZE));
	}

	if (StringHelper::equalsIgnoreCase(option, LOG4CXX_STR("BLOCKING"), LOG4CXX_STR("blocking")))
	{
		setBlocking(OptionConverter::toBoolean(value, true));
	}
	else
	{
		AppenderSkeleton::setOption(option, value);
	}
}


void AsyncAppender::doAppend(const spi::LoggingEventPtr& event, Pool& pool1)
{
	std::lock_guard<std::recursive_mutex> lock(mutex);

	doAppendImpl(event, pool1);
}

void AsyncAppender::append(const spi::LoggingEventPtr& event, Pool& p)
{
	//
	//   if dispatcher has died then
	//      append subsequent events synchronously
	//
	if (!dispatcher.joinable() || bufferSize <= 0)
	{
		std::unique_lock<std::mutex> lock(appenders->getMutex());
		appenders->appendLoopOnAppenders(event, p);
		return;
	}

	// Set the NDC and thread name for the calling thread as these
	// LoggingEvent fields were not set at event creation time.
	LogString ndcVal;
	event->getNDC(ndcVal);
	event->getThreadName();
	// Get a copy of this thread's MDC.
	event->getMDCCopy();


	{
		std::unique_lock<std::mutex> lock(bufferMutex);

		while (true)
		{
			size_t previousSize = buffer.size();

			if (previousSize < (size_t)bufferSize)
			{
				buffer.push_back(event);

				if (previousSize == 0)
				{
					bufferNotEmpty.notify_all();
				}

				break;
			}

			//
			//   Following code is only reachable if buffer is full
			//
			//
			//   if blocking and thread is not already interrupted
			//      and not the dispatcher then
			//      wait for a buffer notification
			bool discard = true;

			if (blocking
				//&& !Thread::interrupted()
				&& (dispatcher.get_id() != std::this_thread::get_id()) )
			{
				try
				{
					bufferNotFull.wait(lock);
					discard = false;
				}
				catch (InterruptedException&)
				{
					//
					//  reset interrupt status so
					//    calling code can see interrupt on
					//    their next wait or sleep.
					//Thread::currentThreadInterrupt();
				}
			}

			//
			//   if blocking is false or thread has been interrupted
			//   add event to discard map.
			//
			if (discard)
			{
				LogString loggerName = event->getLoggerName();
				DiscardMap::iterator iter = discardMap->find(loggerName);

				if (iter == discardMap->end())
				{
					DiscardSummary summary(event);
					discardMap->insert(DiscardMap::value_type(loggerName, summary));
				}
				else
				{
					(*iter).second.add(event);
				}

				break;
			}
		}
	}
}


void AsyncAppender::close()
{
	{
		std::unique_lock<std::mutex> lock(bufferMutex);
		closed = true;
		bufferNotEmpty.notify_all();
		bufferNotFull.notify_all();
	}

	if ( dispatcher.joinable() )
	{
		dispatcher.join();
	}

	{
		std::unique_lock<std::mutex> lock(appenders->getMutex());
		AppenderList appenderList = appenders->getAllAppenders();

		for (AppenderList::iterator iter = appenderList.begin();
			iter != appenderList.end();
			iter++)
		{
			(*iter)->close();
		}
	}
}

AppenderList AsyncAppender::getAllAppenders() const
{
	return appenders->getAllAppenders();
}

AppenderPtr AsyncAppender::getAppender(const LogString& n) const
{
	return appenders->getAppender(n);
}

bool AsyncAppender::isAttached(const AppenderPtr appender) const
{
	return appenders->isAttached(appender);
}

bool AsyncAppender::requiresLayout() const
{
	return false;
}

void AsyncAppender::removeAllAppenders()
{
	appenders->removeAllAppenders();
}

void AsyncAppender::removeAppender(const AppenderPtr appender)
{
	appenders->removeAppender(appender);
}

void AsyncAppender::removeAppender(const LogString& n)
{
	appenders->removeAppender(n);
}

bool AsyncAppender::getLocationInfo() const
{
	return locationInfo;
}

void AsyncAppender::setLocationInfo(bool flag)
{
	locationInfo = flag;
}


void AsyncAppender::setBufferSize(int size)
{
	if (size < 0)
	{
		throw IllegalArgumentException(LOG4CXX_STR("size argument must be non-negative"));
	}

	std::unique_lock<std::mutex> lock(bufferMutex);
	bufferSize = (size < 1) ? 1 : size;
	bufferNotFull.notify_all();
}

int AsyncAppender::getBufferSize() const
{
	return bufferSize;
}

void AsyncAppender::setBlocking(bool value)
{
	std::unique_lock<std::mutex> lock(bufferMutex);
	blocking = value;
	bufferNotFull.notify_all();
}

bool AsyncAppender::getBlocking() const
{
	return blocking;
}

AsyncAppender::DiscardSummary::DiscardSummary(const LoggingEventPtr& event) :
	maxEvent(event), count(1)
{
}

AsyncAppender::DiscardSummary::DiscardSummary(const DiscardSummary& src) :
	maxEvent(src.maxEvent), count(src.count)
{
}

AsyncAppender::DiscardSummary& AsyncAppender::DiscardSummary::operator=(const DiscardSummary& src)
{
	maxEvent = src.maxEvent;
	count = src.count;
	return *this;
}

void AsyncAppender::DiscardSummary::add(const LoggingEventPtr& event)
{
	if (event->getLevel()->toInt() > maxEvent->getLevel()->toInt())
	{
		maxEvent = event;
	}

	count++;
}

LoggingEventPtr AsyncAppender::DiscardSummary::createEvent(Pool& p)
{
	LogString msg(LOG4CXX_STR("Discarded "));
	StringHelper::toString(count, p, msg);
	msg.append(LOG4CXX_STR(" messages due to a full event buffer including: "));
	msg.append(maxEvent->getMessage());
	return LoggingEventPtr( new LoggingEvent(
				maxEvent->getLoggerName(),
				maxEvent->getLevel(),
				msg,
				LocationInfo::getLocationUnavailable()) );
}

::log4cxx::spi::LoggingEventPtr
AsyncAppender::DiscardSummary::createEvent(::log4cxx::helpers::Pool& p,
	size_t discardedCount)
{
	LogString msg(LOG4CXX_STR("Discarded "));
	StringHelper::toString(discardedCount, p, msg);
	msg.append(LOG4CXX_STR(" messages due to a full event buffer"));

	return LoggingEventPtr( new LoggingEvent(
				LOG4CXX_STR(""),
				log4cxx::Level::getError(),
				msg,
				LocationInfo::getLocationUnavailable()) );
}

void AsyncAppender::dispatch()
{
	bool isActive = true;

	try
	{
		while (isActive)
		{
			//
			//   process events after lock on buffer is released.
			//
			Pool p;
			LoggingEventList events;
			{
				std::unique_lock<std::mutex> lock(bufferMutex);
				size_t bufferSize = buffer.size();
				isActive = !closed;

				while ((bufferSize == 0) && isActive)
				{
					bufferNotEmpty.wait(lock);
					bufferSize = buffer.size();
					isActive = !closed;
				}

				for (LoggingEventList::iterator eventIter = buffer.begin();
					eventIter != buffer.end();
					eventIter++)
				{
					events.push_back(*eventIter);
				}

				for (DiscardMap::iterator discardIter = discardMap->begin();
					discardIter != discardMap->end();
					discardIter++)
				{
					events.push_back(discardIter->second.createEvent(p));
				}

				buffer.clear();
				discardMap->clear();
				bufferNotFull.notify_all();
			}

			for (LoggingEventList::iterator iter = events.begin();
				iter != events.end();
				iter++)
			{
				appenders->appendLoopOnAppenders(*iter, p);
			}
		}
	}
	catch (InterruptedException&)
	{
		//Thread::currentThreadInterrupt();
	}
	catch (...)
	{
	}

}
