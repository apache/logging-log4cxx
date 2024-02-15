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


#include <log4cxx/asyncappender.h>


#include <log4cxx/helpers/loglog.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/private/appenderskeleton_priv.h>
#include <thread>
#include <condition_variable>

#if LOG4CXX_EVENTS_AT_EXIT
#include <log4cxx/private/atexitregistry.h>
#endif

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;

#if 15 < LOG4CXX_ABI_VERSION
namespace
{
#endif

/**
 * The default buffer size is set to 128 events.
*/
enum { DEFAULT_BUFFER_SIZE = 128 };

class DiscardSummary
{
	private:
		/**
		 * First event of the highest severity.
		*/
		::LOG4CXX_NS::spi::LoggingEventPtr maxEvent;

		/**
		* Total count of messages discarded.
		*/
		int count;

	public:
		/**
		 * Create new instance.
		 *
		 * @param event event, may not be null.
		*/
		DiscardSummary(const ::LOG4CXX_NS::spi::LoggingEventPtr& event);
		/** Copy constructor.  */
		DiscardSummary(const DiscardSummary& src);
		/** Assignment operator. */
		DiscardSummary& operator=(const DiscardSummary& src);

		/**
		 * Add discarded event to summary.
		 *
		 * @param event event, may not be null.
		*/
		void add(const ::LOG4CXX_NS::spi::LoggingEventPtr& event);

		/**
		 * Create event with summary information.
		 *
		 * @return new event.
		 */
		::LOG4CXX_NS::spi::LoggingEventPtr createEvent(::LOG4CXX_NS::helpers::Pool& p);

		static
		::LOG4CXX_NS::spi::LoggingEventPtr createEvent(::LOG4CXX_NS::helpers::Pool& p,
			size_t discardedCount);
};

typedef std::map<LogString, DiscardSummary> DiscardMap;

#if 15 < LOG4CXX_ABI_VERSION
}
#endif

#define USE_ATOMIC_QUEUE 1
#if USE_ATOMIC_QUEUE
#include <atomic>
namespace
{
static const int CACHE_LINE_SIZE = 128;
class AtomicQueue
{
public:
	struct alignas(CACHE_LINE_SIZE) Node
	{
		LoggingEventPtr data;
		Node* next;
		Node(const LoggingEventPtr& event, Node* n)
			: data(event)
			, next(n)
		{ }
	};

	AtomicQueue() : m_head(0) {}

	void push(const LoggingEventPtr& event)
	{
		auto n = new Node(event, m_head.load(std::memory_order_relaxed));
		while (!m_head.compare_exchange_weak(n->next, n, std::memory_order_release))
		{
		}
	}

	Node* pop_all(void)
	{
		return m_head.exchange(0, std::memory_order_consume);
	}

	Node* pop_all_reverse(void)
	{
		Node* first = 0;
		auto last = pop_all();
		while (last)
		{
			auto tmp = last;
			last = last->next;
			tmp->next = first;
			first = tmp;
		}
		return first;
	}
private:
	std::atomic<Node*> m_head;
};
} // namespace
#endif

struct AsyncAppender::AsyncAppenderPriv : public AppenderSkeleton::AppenderSkeletonPrivate
{
	AsyncAppenderPriv() :
		AppenderSkeletonPrivate(),
		buffer(),
		bufferSize(DEFAULT_BUFFER_SIZE),
		appenders(pool),
		dispatcher(),
		locationInfo(false),
		blocking(true)
#if LOG4CXX_EVENTS_AT_EXIT
		, atExitRegistryRaii([this]{atExitActivated();})
#endif
	{
	}

#if LOG4CXX_EVENTS_AT_EXIT
	void atExitActivated()
	{
		std::unique_lock<std::mutex> lock(bufferMutex);
		bufferNotFull.wait(lock, [this]() -> bool
			{ return buffer.empty() || closed; }
		);
	}
#endif

#if LOG4CXX_ABI_VERSION <= 15 || !(USE_ATOMIC_QUEUE)
	/**
	 * Event buffer.
	*/
	LoggingEventList buffer;
#endif

	/**
	 *  Mutex used to guard access to buffer and discardMap.
	 */
	std::mutex bufferMutex;

	std::condition_variable bufferNotFull;
	std::condition_variable bufferNotEmpty;

	/**
	  * Map of DiscardSummary objects keyed by logger name.
	*/
	DiscardMap discardMap;

	/**
	 * Buffer size.
	*/
	int bufferSize;

	/**
	 * Nested appenders.
	*/
	helpers::AppenderAttachableImpl appenders;

	/**
	 *  Dispatcher.
	 */
	std::thread dispatcher;

	/**
	 * Should location info be included in dispatched messages.
	*/
	bool locationInfo;

	/**
	 * Does appender block when buffer is full.
	*/
	bool blocking;

#if LOG4CXX_EVENTS_AT_EXIT
	helpers::AtExitRegistry::Raii atExitRegistryRaii;
#endif

#if USE_ATOMIC_QUEUE
	/**
	 * Pending events
	*/
	alignas(CACHE_LINE_SIZE) AtomicQueue eventList;

	/**
	 * The number of pending events.
	*/
	alignas(CACHE_LINE_SIZE) std::atomic<int> approxListSize;
#endif
};


IMPLEMENT_LOG4CXX_OBJECT(AsyncAppender)

#define priv static_cast<AsyncAppenderPriv*>(m_priv.get())

AsyncAppender::AsyncAppender()
	: AppenderSkeleton(std::make_unique<AsyncAppenderPriv>())
{
}

AsyncAppender::~AsyncAppender()
{
	finalize();
}

void AsyncAppender::addAppender(const AppenderPtr newAppender)
{
	priv->appenders.addAppender(newAppender);
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
	doAppendImpl(event, pool1);
}

void AsyncAppender::append(const spi::LoggingEventPtr& event, Pool& p)
{
	if (priv->bufferSize <= 0)
	{
		priv->appenders.appendLoopOnAppenders(event, p);
	}

	// Set the NDC and MDC for the calling thread as these
	// LoggingEvent fields were not set at event creation time.
	LogString ndcVal;
	event->getNDC(ndcVal);
	// Get a copy of this thread's MDC.
	event->getMDCCopy();

	if (!priv->dispatcher.joinable())
	{
		std::unique_lock<std::mutex> lock(priv->bufferMutex);
		if (!priv->dispatcher.joinable())
			priv->dispatcher = ThreadUtility::instance()->createThread( LOG4CXX_STR("AsyncAppender"), &AsyncAppender::dispatch, this );
	}
	while (true)
	{
#if USE_ATOMIC_QUEUE
		auto newSize = ++priv->approxListSize;
		if (newSize <= priv->bufferSize)
		{
			priv->eventList.push(event);
			if (1 == newSize)
				priv->bufferNotEmpty.notify_all();
			break;
		}
		else
			--priv->approxListSize;
		//
		//   Following code is only reachable if buffer is full
		//
		std::unique_lock<std::mutex> lock(priv->bufferMutex);
#else
		std::unique_lock<std::mutex> lock(priv->bufferMutex);
		size_t previousSize = priv->buffer.size();

		if (previousSize < (size_t)priv->bufferSize)
		{
			priv->buffer.push_back(event);

			if (previousSize == 0)
			{
				priv->bufferNotEmpty.notify_all();
			}

			break;
		}
		//
		//   Following code is only reachable if buffer is full
		//
#endif
		//
		//   if blocking and thread is not already interrupted
		//      and not the dispatcher then
		//      wait for a buffer notification
		bool discard = true;

		if (priv->blocking
			&& !priv->closed
			&& (priv->dispatcher.get_id() != std::this_thread::get_id()) )
		{
			priv->bufferNotFull.wait(lock, [this]()
			{
				return priv->buffer.empty();
			});
			discard = false;
		}

		//
		//   if blocking is false or thread has been interrupted
		//   add event to discard map.
		//
		if (discard)
		{
			LogString loggerName = event->getLoggerName();
			DiscardMap::iterator iter = priv->discardMap.find(loggerName);

			if (iter == priv->discardMap.end())
			{
				DiscardSummary summary(event);
				priv->discardMap.insert(DiscardMap::value_type(loggerName, summary));
			}
			else
			{
				(*iter).second.add(event);
			}

			break;
		}
	}
}

void AsyncAppender::close()
{
	{
		std::lock_guard<std::mutex> lock(priv->bufferMutex);
		priv->closed = true;
		priv->bufferNotEmpty.notify_all();
		priv->bufferNotFull.notify_all();
	}

	if ( priv->dispatcher.joinable() )
	{
#if USE_ATOMIC_QUEUE
		// Queue a special event that will terminate the dispatch thread
		priv->eventList.push(LoggingEventPtr());
#endif
		priv->dispatcher.join();
	}

	for (auto item : priv->appenders.getAllAppenders())
	{
		item->close();
	}
}

AppenderList AsyncAppender::getAllAppenders() const
{
	return priv->appenders.getAllAppenders();
}

AppenderPtr AsyncAppender::getAppender(const LogString& n) const
{
	return priv->appenders.getAppender(n);
}

bool AsyncAppender::isAttached(const AppenderPtr appender) const
{
	return priv->appenders.isAttached(appender);
}

bool AsyncAppender::requiresLayout() const
{
	return false;
}

void AsyncAppender::removeAllAppenders()
{
	priv->appenders.removeAllAppenders();
}

void AsyncAppender::removeAppender(const AppenderPtr appender)
{
	priv->appenders.removeAppender(appender);
}

void AsyncAppender::removeAppender(const LogString& n)
{
	priv->appenders.removeAppender(n);
}

bool AsyncAppender::getLocationInfo() const
{
	return priv->locationInfo;
}

void AsyncAppender::setLocationInfo(bool flag)
{
	priv->locationInfo = flag;
}


void AsyncAppender::setBufferSize(int size)
{
	if (size < 0)
	{
		throw IllegalArgumentException(LOG4CXX_STR("size argument must be non-negative"));
	}

	std::lock_guard<std::mutex> lock(priv->bufferMutex);
	priv->bufferSize = (size < 1) ? 1 : size;
	priv->bufferNotFull.notify_all();
}

int AsyncAppender::getBufferSize() const
{
	return priv->bufferSize;
}

void AsyncAppender::setBlocking(bool value)
{
	std::lock_guard<std::mutex> lock(priv->bufferMutex);
	priv->blocking = value;
	priv->bufferNotFull.notify_all();
}

bool AsyncAppender::getBlocking() const
{
	return priv->blocking;
}

DiscardSummary::DiscardSummary(const LoggingEventPtr& event) :
	maxEvent(event), count(1)
{
}

DiscardSummary::DiscardSummary(const DiscardSummary& src) :
	maxEvent(src.maxEvent), count(src.count)
{
}

DiscardSummary& DiscardSummary::operator=(const DiscardSummary& src)
{
	maxEvent = src.maxEvent;
	count = src.count;
	return *this;
}

void DiscardSummary::add(const LoggingEventPtr& event)
{
	if (event->getLevel()->toInt() > maxEvent->getLevel()->toInt())
	{
		maxEvent = event;
	}

	count++;
}

LoggingEventPtr DiscardSummary::createEvent(Pool& p)
{
	LogString msg(LOG4CXX_STR("Discarded "));
	StringHelper::toString(count, p, msg);
	msg.append(LOG4CXX_STR(" messages due to a full event buffer including: "));
	msg.append(maxEvent->getMessage());
	return std::make_shared<LoggingEvent>(
				maxEvent->getLoggerName(),
				maxEvent->getLevel(),
				msg,
				LocationInfo::getLocationUnavailable() );
}

::LOG4CXX_NS::spi::LoggingEventPtr
DiscardSummary::createEvent(::LOG4CXX_NS::helpers::Pool& p,
	size_t discardedCount)
{
	LogString msg(LOG4CXX_STR("Discarded "));
	StringHelper::toString(discardedCount, p, msg);
	msg.append(LOG4CXX_STR(" messages due to a full event buffer"));

	return std::make_shared<LoggingEvent>(
				LOG4CXX_STR(""),
				LOG4CXX_NS::Level::getError(),
				msg,
				LocationInfo::getLocationUnavailable() );
}

void AsyncAppender::dispatch()
{
	Pool p;
	bool isActive = true;

	while (isActive)
	{
		LoggingEventList events;
#if USE_ATOMIC_QUEUE
		auto eventList = priv->eventList.pop_all_reverse();
		if (!eventList)
		{
			std::unique_lock<std::mutex> lock(priv->bufferMutex);
			priv->bufferNotEmpty.wait(lock, [this, &eventList]() -> bool
				{
					eventList = priv->eventList.pop_all_reverse();
					return eventList || priv->closed;
				}
			);
		}
		priv->approxListSize = 0;
		priv->bufferNotFull.notify_all();
		while (eventList)
		{
			if (eventList->data)
				events.push_back(eventList->data);
			else
				isActive = false;
			auto next = eventList->next;
			delete eventList;
			eventList = next;
		}
		{
			std::unique_lock<std::mutex> lock(priv->bufferMutex);
			for (auto item : priv->discardMap)
				events.push_back(item.second.createEvent(p));
			priv->discardMap.clear();
		}
#else
		//
		//   process events after lock on buffer is released.
		//
		{
			std::unique_lock<std::mutex> lock(priv->bufferMutex);
			priv->bufferNotEmpty.wait(lock, [this]() -> bool
				{ return 0 < priv->buffer.size() || priv->closed; }
			);
			isActive = !priv->closed;

			for (auto eventItem : priv->buffer)
			{
				events.push_back(eventItem);
			}

			for (auto discardItem : priv->discardMap)
			{
				events.push_back(discardItem.second.createEvent(p));
			}

			priv->buffer.clear();
			priv->discardMap.clear();
			priv->bufferNotFull.notify_all();
		}
#endif

		for (auto item : events)
		{
			try
			{
				priv->appenders.appendLoopOnAppenders(item, p);
			}
			catch (std::exception& ex)
			{
				if (isActive)
				{
					priv->errorHandler->error(LOG4CXX_STR("async dispatcher"), ex, 0, item);
					isActive = false;
				}
			}
			catch (...)
			{
				if (isActive)
				{
					priv->errorHandler->error(LOG4CXX_STR("async dispatcher"));
					isActive = false;
				}
			}
		}
	}

}
