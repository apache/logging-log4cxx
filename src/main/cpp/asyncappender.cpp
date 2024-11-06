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
#include <atomic>
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
		LoggingEventPtr maxEvent;

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
		DiscardSummary(const LoggingEventPtr& event);
		/** Copy constructor.  */
		DiscardSummary(const DiscardSummary& src);
		/** Assignment operator. */
		DiscardSummary& operator=(const DiscardSummary& src);

		/**
		 * Add discarded event to summary.
		 *
		 * @param event event, may not be null.
		*/
		void add(const LoggingEventPtr& event);

		/**
		 * Create an event with a discard count and the message from \c maxEvent.
		 *
		 * @return the new event.
		 */
		LoggingEventPtr createEvent(Pool& p);

#if LOG4CXX_ABI_VERSION <= 15
		static
		::LOG4CXX_NS::spi::LoggingEventPtr createEvent(::LOG4CXX_NS::helpers::Pool& p,
			size_t discardedCount);
#endif

		/**
		* The number of messages discarded.
		*/
		int getCount() const { return count; }
};

typedef std::map<LogString, DiscardSummary> DiscardMap;

#if 15 < LOG4CXX_ABI_VERSION
}
#endif

#ifdef __cpp_lib_hardware_interference_size
	using std::hardware_constructive_interference_size;
	using std::hardware_destructive_interference_size;
#else
	// 64 bytes on x86-64 │ L1_CACHE_BYTES │ L1_CACHE_SHIFT │ __cacheline_aligned │ ...
	constexpr std::size_t hardware_constructive_interference_size = 64;
	constexpr std::size_t hardware_destructive_interference_size = 64;
#endif

struct AsyncAppender::AsyncAppenderPriv : public AppenderSkeleton::AppenderSkeletonPrivate
{
	AsyncAppenderPriv()
		: AppenderSkeletonPrivate()
		, buffer(DEFAULT_BUFFER_SIZE)
		, bufferSize(DEFAULT_BUFFER_SIZE)
		, dispatcher()
		, locationInfo(false)
		, blocking(true)
#if LOG4CXX_EVENTS_AT_EXIT
		, atExitRegistryRaii([this]{stopDispatcher();})
#endif
		, eventCount(0)
		, dispatchedCount(0)
		, commitCount(0)
		{ }

	~AsyncAppenderPriv()
	{
		stopDispatcher();
	}

	/**
	 * Event buffer.
	*/
	struct EventData
	{
		LoggingEventPtr event;
		size_t pendingCount;
	};
	std::vector<EventData> buffer;

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
	 * The maximum number of undispatched events.
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

	void stopDispatcher()
	{
		this->setClosed();
		bufferNotEmpty.notify_all();
		bufferNotFull.notify_all();

		if (dispatcher.joinable())
		{
			dispatcher.join();
		}
	}

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

	/**
	 * Used to calculate the buffer position at which to store the next event.
	*/
	alignas(hardware_constructive_interference_size) std::atomic<size_t> eventCount;

	/**
	 * Used to calculate the buffer position from which to extract the next event.
	*/
	alignas(hardware_constructive_interference_size) std::atomic<size_t> dispatchedCount;

	/**
	 * Used to communicate to the dispatch thread when an event is committed in buffer.
	*/
	alignas(hardware_constructive_interference_size) std::atomic<size_t> commitCount;

	bool isClosed()
	{
		std::lock_guard<std::mutex> lock(this->bufferMutex);
		return this->closed;
	}

	void setClosed()
	{
		std::lock_guard<std::mutex> lock(this->bufferMutex);
		this->closed = true;
	}

	/**
	 * Used to ensure the dispatch thread does not wait when a logging thread is waiting.
	*/
	int blockedCount{0};
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

	// Get a copy of this thread's diagnostic context
	event->LoadDC();

	if (!priv->dispatcher.joinable())
	{
		std::lock_guard<std::recursive_mutex> lock(priv->mutex);
		if (!priv->dispatcher.joinable())
			priv->dispatcher = ThreadUtility::instance()->createThread( LOG4CXX_STR("AsyncAppender"), &AsyncAppender::dispatch, this );
	}
	while (true)
	{
		auto pendingCount = priv->eventCount - priv->dispatchedCount;
		if (0 <= pendingCount && pendingCount < priv->bufferSize)
		{
			// Claim a slot in the ring buffer
			auto oldEventCount = priv->eventCount++;
			auto index = oldEventCount % priv->buffer.size();
			// Wait for a free slot
			while (priv->bufferSize <= oldEventCount - priv->dispatchedCount)
				std::this_thread::yield(); // Allow the dispatch thread to free a slot
			// Write to the ring buffer
			priv->buffer[index] = AsyncAppenderPriv::EventData{event, pendingCount};
			// Notify the dispatch thread that an event has been added
			auto failureCount = 0;
			auto savedEventCount = oldEventCount;
			while (!priv->commitCount.compare_exchange_weak(oldEventCount, oldEventCount + 1, std::memory_order_release))
			{
				oldEventCount = savedEventCount;
				if (2 < ++failureCount) // Did the scheduler suspend a thread between claiming a slot and advancing commitCount?
					std::this_thread::yield(); // Wait a bit
			}
			priv->bufferNotEmpty.notify_all();
			break;
		}
		//
		//   Following code is only reachable if buffer is full or eventCount has overflowed
		//
		std::unique_lock<std::mutex> lock(priv->bufferMutex);
		priv->bufferNotEmpty.notify_all();
		//
		//   if blocking and thread is not already interrupted
		//      and not the dispatcher then
		//      wait for a buffer notification
		bool discard = true;

		if (priv->blocking
			&& !priv->closed
			&& (priv->dispatcher.get_id() != std::this_thread::get_id()) )
		{
			++priv->blockedCount;
			priv->bufferNotFull.wait(lock, [this]()
			{
				return priv->eventCount - priv->dispatchedCount < priv->bufferSize;
			});
			--priv->blockedCount;
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
	priv->stopDispatcher();
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
	priv->buffer.resize(priv->bufferSize);
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

#if LOG4CXX_ABI_VERSION <= 15
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
#endif


void AsyncAppender::dispatch()
{
	size_t discardCount = 0;
	std::vector<size_t> pendingCountHistogram(priv->bufferSize, 0);
	bool isActive = true;

	while (isActive)
	{
		Pool p;
		LoggingEventList events;
		events.reserve(priv->bufferSize);
		for (int count = 0; count < 2 && priv->dispatchedCount == priv->commitCount; ++count)
			std::this_thread::yield(); // Wait a bit
		if (priv->dispatchedCount == priv->commitCount)
		{
			std::unique_lock<std::mutex> lock(priv->bufferMutex);
			priv->bufferNotEmpty.wait(lock, [this]() -> bool
				{ return 0 < priv->blockedCount || priv->dispatchedCount != priv->commitCount || priv->closed; }
			);
		}
		isActive = !priv->isClosed();

		while (events.size() < priv->bufferSize && priv->dispatchedCount != priv->commitCount)
		{
			auto index = priv->dispatchedCount % priv->buffer.size();
			const auto& data = priv->buffer[index];
			events.push_back(data.event);
			if (data.pendingCount < pendingCountHistogram.size())
				++pendingCountHistogram[data.pendingCount];
			++priv->dispatchedCount;
		}
		priv->bufferNotFull.notify_all();
		{
			std::lock_guard<std::mutex> lock(priv->bufferMutex);
			for (auto discardItem : priv->discardMap)
			{
				events.push_back(discardItem.second.createEvent(p));
				discardCount += discardItem.second.getCount();
			}
			priv->discardMap.clear();
		}

		for (auto item : events)
		{
			try
			{
				priv->appenders.appendLoopOnAppenders(item, p);
			}
			catch (std::exception& ex)
			{
				if (!priv->isClosed())
				{
					priv->errorHandler->error(LOG4CXX_STR("async dispatcher"), ex, 0, item);
					isActive = false;
				}
			}
			catch (...)
			{
				if (!priv->isClosed())
				{
					priv->errorHandler->error(LOG4CXX_STR("async dispatcher"));
					isActive = false;
				}
			}
		}
	}
	if (LogLog::isDebugEnabled())
	{
		Pool p;
		LogString msg(LOG4CXX_STR("AsyncAppender"));
		msg += LOG4CXX_STR(" discardCount ");
		StringHelper::toString(discardCount, p, msg);
		msg += LOG4CXX_STR(" pendingCountHistogram");
		for (auto item : pendingCountHistogram)
		{
			msg += logchar(' ');
			StringHelper::toString(item, p, msg);
		}
		LogLog::debug(msg);
	}

}
