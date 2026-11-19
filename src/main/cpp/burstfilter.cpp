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

#include <log4cxx/logstring.h>
#include <log4cxx/filter/burstfilter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/private/filter_priv.h>
#include <algorithm>
#include <chrono>
#include <limits>
#include <mutex>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::filter;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

#define priv static_cast<BurstFilterPrivate*>(m_priv.get())

struct BurstFilter::BurstFilterPrivate : public FilterPrivate
{
	using Clock = std::chrono::steady_clock;

	BurstFilterPrivate()
		: level(Level::getWarn())
		, rate(10)
		, maxBurst(0)
	{
		fill();
	}

	/**
	The most severe level that is subject to the rate limit.
	*/
	LevelPtr level;
	/**
	The number of tokens added to the bucket each second.
	*/
	int rate;
	/**
	The bucket capacity, or zero to use ten times the rate.
	*/
	int maxBurst;

	std::mutex mutex;
	double tokens;
	Clock::time_point lastRefill;

	int getCapacity() const
	{
		if (0 < this->maxBurst)
			return this->maxBurst;
		const int maxRate = (std::numeric_limits<int>::max)() / 10;
		return (std::min)(this->rate, maxRate) * 10;
	}

	void fill()
	{
		this->tokens = getCapacity();
		this->lastRefill = Clock::now();
	}

	/**
	Remove a token from the bucket if one is available.
	*/
	bool tryAcquire()
	{
		std::lock_guard<std::mutex> lock(this->mutex);
		auto now = Clock::now();
		std::chrono::duration<double> elapsed = now - this->lastRefill;
		if (0 < elapsed.count())
		{
			this->tokens = (std::min)
				( static_cast<double>(getCapacity())
				, this->tokens + elapsed.count() * this->rate
				);
			this->lastRefill = now;
		}
		if (this->tokens < 1)
			return false;
		this->tokens -= 1;
		return true;
	}
};

IMPLEMENT_LOG4CXX_OBJECT(BurstFilter)

BurstFilter::BurstFilter()
	: Filter(std::make_unique<BurstFilterPrivate>())
{
}

BurstFilter::~BurstFilter() {}

namespace
{

/**
 * The positive integer in \c value, or zero (with a warning)
 * if \c value is not a positive integer.
 */
int toPositiveInt(const LogString& option, const LogString& value)
{
	int result = OptionConverter::toInt(value, 0);
	if (result <= 0)
	{
		LogLog::warn(LOG4CXX_STR("Ignoring BurstFilter ") + option
			+ LOG4CXX_STR(" value [") + value + LOG4CXX_STR("] which is not a positive integer"));
		result = 0;
	}
	return result;
}

} // namespace

void BurstFilter::setOption(const LogString& option, const LogString& value)
{
	if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("LEVEL"), LOG4CXX_STR("level")))
	{
		setLevel(OptionConverter::toLevel(value, priv->level));
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("RATE"), LOG4CXX_STR("rate")))
	{
		if (auto newValue = toPositiveInt(option, value))
			setRate(newValue);
	}
	else if (StringHelper::equalsIgnoreCase(option,
			LOG4CXX_STR("MAXBURST"), LOG4CXX_STR("maxburst")))
	{
		if (auto newValue = toPositiveInt(option, value))
			setMaxBurst(newValue);
	}
	else
		Filter::setOption(option, value);
}

bool BurstFilter::activateOptions()
{
	std::lock_guard<std::mutex> lock(priv->mutex);
	priv->fill();
	return true;
}

void BurstFilter::setLevel(const LevelPtr& newValue)
{
	priv->level = newValue;
}

const LevelPtr& BurstFilter::getLevel() const
{
	return priv->level;
}

void BurstFilter::setRate(int newValue)
{
	if (newValue <= 0)
	{
		LogLog::warn(LOG4CXX_STR("Ignoring BurstFilter rate which is not positive"));
		return;
	}
	std::lock_guard<std::mutex> lock(priv->mutex);
	priv->rate = newValue;
}

int BurstFilter::getRate() const
{
	std::lock_guard<std::mutex> lock(priv->mutex);
	return priv->rate;
}

void BurstFilter::setMaxBurst(int newValue)
{
	if (newValue <= 0)
	{
		LogLog::warn(LOG4CXX_STR("Ignoring BurstFilter maximum burst which is not positive"));
		return;
	}
	std::lock_guard<std::mutex> lock(priv->mutex);
	priv->maxBurst = newValue;
}

int BurstFilter::getMaxBurst() const
{
	std::lock_guard<std::mutex> lock(priv->mutex);
	return priv->getCapacity();
}

Filter::FilterDecision BurstFilter::decide(const spi::LoggingEventPtr& event) const
{
	if (priv->level && priv->level->toInt() < event->getLevel()->toInt())
		return Filter::NEUTRAL;
	return priv->tryAcquire() ? Filter::NEUTRAL : Filter::DENY;
}
