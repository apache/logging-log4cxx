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

#ifndef _LOG4CXX_FILTER_BURST_FILTER_H
#define _LOG4CXX_FILTER_BURST_FILTER_H

#include <log4cxx/spi/filter.h>
#include <log4cxx/level.h>

namespace LOG4CXX_NS
{
namespace filter
{
/**
A filter that limits the rate at which logging events are passed on,
so a burst of logging requests (for example, an error repeated in a tight loop)
cannot flood the output of an appender.

Logging events with a level that is as severe as or less severe than
the <code>Level</code> option are subject to the rate limit.
More severe logging events are never dropped by this filter.

The rate limit is a <a href="https://en.wikipedia.org/wiki/Token_bucket">token bucket</a>
that holds at most <code>MaxBurst</code> tokens and is refilled
at <code>Rate</code> tokens per second.
Each rate limited logging event uses one token.
When there is no token available, the logging event is dropped.
In other words, after a burst of <code>MaxBurst</code> logging events,
at most <code>Rate</code> logging events per second are passed on
until the rate of logging requests falls below <code>Rate</code>.

The {@link #decide decide} method returns
{@link spi::Filter#DENY DENY} when the logging event is dropped
and {@link spi::Filter#NEUTRAL NEUTRAL} otherwise,
so the remaining filters in the chain are consulted for the logging events that are passed on.

For example, the following configuration allows bursts of up to 100 logging events
and an average of 16 logging events per second at level WARN and below,
while all ERROR and FATAL logging events are written:

~~~{.xml}
<appender name="A1" class="FileAppender">
  <param name="File" value="logs/app.log" />
  <layout class="PatternLayout">
    <param name="ConversionPattern" value="%d %-5p %c - %m%n" />
  </layout>
  <filter class="BurstFilter">
    <param name="Level" value="WARN" />
    <param name="Rate" value="16" />
    <param name="MaxBurst" value="100" />
  </filter>
</appender>
~~~

The equivalent [properties file](@ref log4cxx::PropertyConfigurator) configuration is:

~~~{.properties}
log4j.appender.A1.filter.1=BurstFilter
log4j.appender.A1.filter.1.Level=WARN
log4j.appender.A1.filter.1.Rate=16
log4j.appender.A1.filter.1.MaxBurst=100
~~~

If configuring programmatically, call {@link #activateOptions activateOptions}
after changing an option so that the bucket is refilled to its new capacity.
*/
class LOG4CXX_EXPORT BurstFilter : public spi::Filter
{
	private:
		struct BurstFilterPrivate;

	public:
		typedef spi::Filter BASE_CLASS;
		DECLARE_LOG4CXX_OBJECT(BurstFilter)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(BurstFilter)
		LOG4CXX_CAST_ENTRY_CHAIN(BASE_CLASS)
		END_LOG4CXX_CAST_MAP()

		BurstFilter();
		~BurstFilter();

		/**
		\copybrief spi::OptionHandler::setOption()

		Supported options | Supported values | Default value |
		-------------- | ---------------- | --------------- |
		Level | (\ref burstLevels "1") | WARN |
		Rate | {positive integer} | 10 |
		MaxBurst | {positive integer} | 10 times the Rate |

		\anchor burstLevels (1). One of "Trace", "Debug", "Info", "Warn", "Error", "Fatal", "Off", "All"
		or a custom level in which case it is of the form <code>{levelName}#{registeredClassName}</code>.

		A value that is not a positive integer is ignored with a warning in the
		[Log4cxx internal debugging](internal-debugging.html) output.
		*/
		void setOption(const LogString& option, const LogString& value) override;

		using spi::Filter::activateOptions;
		/**
		\copybrief spi::OptionHandler::activateOptions()

		Fills the bucket with <code>MaxBurst</code> tokens.
		*/
		bool activateOptions() override;

		/**
		Use \c newValue as the most severe level that is subject to the rate limit.
		*/
		void setLevel(const LevelPtr& newValue);

		/**
		The most severe level that is subject to the rate limit.
		*/
		const LevelPtr& getLevel() const;

		/**
		Use \c newValue (which must be positive) as the average number of logging events per second to pass on.
		*/
		void setRate(int newValue);

		/**
		The average number of logging events per second to pass on.
		*/
		int getRate() const;

		/**
		Use \c newValue (which must be positive) as the maximum number of logging events to pass on in a burst.
		*/
		void setMaxBurst(int newValue);

		/**
		The maximum number of logging events to pass on in a burst.
		Ten times the Rate unless set using setMaxBurst() or the <code>MaxBurst</code> option.
		*/
		int getMaxBurst() const;

		/**
		Returns {@link spi::Filter#DENY DENY} if \c event is subject to the rate limit
		and no token is available, otherwise {@link spi::Filter#NEUTRAL NEUTRAL}.
		*/
		FilterDecision decide(const spi::LoggingEventPtr& event) const override;
}; // class BurstFilter
LOG4CXX_PTR_DEF(BurstFilter);
}  // namespace filter
} // namespace log4cxx

#endif // _LOG4CXX_FILTER_BURST_FILTER_H
