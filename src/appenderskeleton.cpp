/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/onlyonceerrorhandler.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/synchronized.h>
#include <apr_atomic.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

AppenderSkeleton::AppenderSkeleton()
: errorHandler(new OnlyOnceErrorHandler()),
  closed(0),
  threshold(Level::getAll()),
  layout(),
  name(),
  headFilter(),
  tailFilter(),
  mutex(getSynchronizationPool())
{
}

AppenderSkeleton::AppenderSkeleton(const LayoutPtr& layout)
: errorHandler(new OnlyOnceErrorHandler()),
  closed(0),
  threshold(Level::getAll()),
  layout(layout),
  name(),
  headFilter(),
  tailFilter(),
  mutex(getSynchronizationPool())
{
}

void AppenderSkeleton::finalize()
{
// An appender might be closed then garbage collected. There is no
// point in closing twice.
	if(closed)
	{
		return;
	}

	close();
}

void AppenderSkeleton::addFilter(const spi::FilterPtr& newFilter)
{
	if(headFilter == 0)
	{
		headFilter = tailFilter = newFilter;
	}
	else
	{
		tailFilter->next = newFilter;
		tailFilter = newFilter;
	}
}

void AppenderSkeleton::clearFilters()
{
	headFilter = tailFilter = 0;
}

bool AppenderSkeleton::isAsSevereAsThreshold(const LevelPtr& level) const
{
	return ((level == 0) || level->isGreaterOrEqual(threshold));
}

void AppenderSkeleton::doAppend(const spi::LoggingEventPtr& event, apr_pool_t* pool)
{
	synchronized sync(mutex);


	if(closed)
	{
                LogLog::error(((LogString) LOG4CXX_STR("Attempted to append to closed appender named ["))
                      + name + LOG4CXX_STR("]."));
		return;
	}

	if(!isAsSevereAsThreshold(event->getLevel()))
	{
		return;
	}

	FilterPtr f = headFilter;


	while(f != 0)
	{
		 switch(f->decide(event))
		 {
			 case Filter::DENY:
				 return;
			 case Filter::ACCEPT:
				 f = 0;
				 break;
			 case Filter::NEUTRAL:
				 f = f->next;
		 }
	}

	append(event, pool);
}

void AppenderSkeleton::setErrorHandler(const spi::ErrorHandlerPtr& errorHandler)
{
	synchronized sync(mutex);

	if(errorHandler == 0)
	{
		// We do not throw exception here since the cause is probably a
		// bad config file.
		LogLog::warn(LOG4CXX_STR("You have tried to set a null error-handler."));
	}
	else
	{
		this->errorHandler = errorHandler;
	}
}

void AppenderSkeleton::setThreshold(const LevelPtr& threshold)
{
	this->threshold = threshold;
}

void AppenderSkeleton::setOption(const LogString& option,
	const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option,
              LOG4CXX_STR("THRESHOLD"), LOG4CXX_STR("threshold")))
	{
		setThreshold(Level::toLevel(value));
	}
}


apr_pool_t* AppenderSkeleton::getSynchronizationPool() {
    static Pool syncPool;
    return syncPool;
}
