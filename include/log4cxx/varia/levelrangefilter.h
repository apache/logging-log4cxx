/***************************************************************************
                          levelrangefilter.h  -  class LevelRangeFilter
                             -------------------
    begin                : dim mai 18 2003
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

#ifndef _LOG4CXX_VARIA_LEVEL_RANGE_FILTER_H
#define _LOG4CXX_VARIA_LEVEL_RANGE_FILTER_H

#include <log4cxx/spi/filter.h>
#include <log4cxx/level.h>

namespace log4cxx
{
	namespace varia
	{
		/**
		This is a very simple filter based on level matching, which can be
		used to reject messages with priorities outside a certain range.

		<p>The filter admits three options <b>LevelMin</b>, <b>LevelMax</b>
		and <b>AcceptOnMatch</b>.

		<p>If the level of the {@link spi::LoggingEvent LoggingEvent} is not 
		between Min and Max (inclusive), then {@link spi::Filter#DENY DENY}
		is returned.

		<p> If the Logging event level is within the specified range, then if
		<b>AcceptOnMatch</b> is true, {@link spi::Filter#ACCEPT ACCEPT} is 
		returned, and if <b>AcceptOnMatch</b> is false, 
		{@link spi::Filter#NEUTRAL NEUTRAL} is returned.

		<p>If <code>LevelMin</code>w is not defined, then there is no
		minimum acceptable level (ie a level is never rejected for
		being too "low"/unimportant).  If <code>LevelMax</code> is not
		defined, then there is no maximum acceptable level (ie a
		level is never rejected for beeing too "high"/important).

		<p>Refer to the {@link
		AppenderSkeleton#setThreshold setThreshold} method
		available to <code>all</code> appenders extending 
		AppenderSkeleton for a more convenient way to
		filter out events by level.
		*/
		class LevelRangeFilter;
		typedef helpers::ObjectPtrT<LevelRangeFilter> LevelRangeFilterPtr;

		class LOG4CXX_EXPORT LevelRangeFilter : public spi::Filter
		{
		private:
			static String LEVEL_MIN_OPTION;
			static String LEVEL_MAX_OPTION;
			static String ACCEPT_ON_MATCH_OPTION;

			/**
			Do we return ACCEPT when a match occurs. Default is
			<code>false</code>, so that later filters get run by default
			*/
			bool acceptOnMatch;
			LevelPtr levelMin;
			LevelPtr levelMax;

		public:
			typedef spi::Filter BASE_CLASS;
			DECLARE_LOG4CXX_OBJECT(LevelRangeFilter)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(LevelRangeFilter)
				LOG4CXX_CAST_ENTRY_CHAIN(BASE_CLASS)
			END_LOG4CXX_CAST_MAP()

			LevelRangeFilter();

			/**
			Set options
			*/
			virtual void setOption(const String& option,
				const String& value);

			/**
			Set the <code>LevelMin</code> option.
			*/
			void setLevelMin(const LevelPtr& levelMin)
				{ this->levelMin = levelMin; }

			/**
			Get the value of the <code>LevelMin</code> option.
			*/
			const LevelPtr& getLevelMin() const
				{ return levelMin; }

			/**
			Set the <code>LevelMax</code> option.
			*/
			void setLevelMax(const LevelPtr& levelMax)
				{ this->levelMax = levelMax; }

			/**
			Get the value of the <code>LevelMax</code> option.
			*/
			const LevelPtr& getLevelMax() const
				{ return levelMax; }

			/**
			Set the <code>AcceptOnMatch</code> option.
			*/
			inline void setAcceptOnMatch(bool acceptOnMatch)
				{ this->acceptOnMatch = acceptOnMatch; }

			/**
			Get the value of the <code>AcceptOnMatch</code> option.
			*/
			inline bool getAcceptOnMatch() const
				{ return acceptOnMatch; }

			/**
			Return the decision of this filter.

			Returns {@link spi::Filter#NEUTRAL NEUTRAL} if the 
			<b>LevelToMatch</b> option is not set or if there is not match.
			Otherwise, if there is a match, then the returned decision is 
			{@link spi::Filter#ACCEPT ACCEPT} if the
			<b>AcceptOnMatch</b> property is set to <code>true</code>. The
			returned decision is {@link spi::Filter#DENY DENY} if the
			<b>AcceptOnMatch</b> property is set to false.
			*/
			FilterDecision decide(const spi::LoggingEventPtr& event);
		}; // class LevelMatchFilter
	}; // namespace varia
}; // namespace log4cxx

#endif // _LOG4CXX_VARIA_LEVEL_RANGE_FILTER_H
