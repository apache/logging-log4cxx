/***************************************************************************
                          levelmatchfilter.h  -  class LevelMatchFilter
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

#ifndef _LOG4CXX_VARIA_LEVEL_MATCH_FILTER_H
#define _LOG4CXX_VARIA_LEVEL_MATCH_FILTER_H

#include <log4cxx/spi/filter.h>
#include <log4cxx/level.h>

namespace log4cxx
{
	class Level;
	
	namespace varia
	{
		/**
		This is a very simple filter based on level matching.

		<p>The filter admits two options <b>LevelToMatch</b> and
		<b>AcceptOnMatch</b>. If there is an exact match between the value
		of the <b>LevelToMatch</b> option and the level of the {@link
		spi::LoggingEvent LoggingEvent}, then the #decide method returns {@link
		spi::Filter#ACCEPT ACCEPT} in case the <b>AcceptOnMatch</b> 
		option value is set to <code>true</code>, if it is <code>false</code>
		then {@link spi::Filter#DENY DENY} is returned. If there is no match,
		{@link spi::Filter#NEUTRAL NEUTRAL} is returned.
		*/
		class LevelMatchFilter;
		typedef helpers::ObjectPtrT<LevelMatchFilter> LevelMatchFilterPtr;

		class LOG4CXX_EXPORT LevelMatchFilter : public spi::Filter
		{
		private:
			static String LEVEL_TO_MATCH_OPTION;
			static String ACCEPT_ON_MATCH_OPTION;

			bool acceptOnMatch;
			LevelPtr levelToMatch;

		public:
			typedef spi::Filter BASE_CLASS;
			DECLARE_LOG4CXX_OBJECT(LevelMatchFilter)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(LevelMatchFilter)
				LOG4CXX_CAST_ENTRY_CHAIN(BASE_CLASS)
			END_LOG4CXX_CAST_MAP()

			LevelMatchFilter();

			/**
			Set options
			*/
			virtual void setOption(const String& option,
				const String& value);

			void setLevelToMatch(const String& levelToMatch);

			const String& getLevelToMatch() const;

			inline void setAcceptOnMatch(bool acceptOnMatch)
				{ this->acceptOnMatch = acceptOnMatch; }

			inline bool getAcceptOnMatch() const
				{ return acceptOnMatch; }

			/**
			Return the decision of this filter.

			Returns {@link spi::Filter#NEUTRAL NEUTRAL} if the 
			<b>LevelToMatch</b> option is not set or if there is not match.
			Otherwise, if there is a match, then the returned decision is 
			{@link spi::Filter#ACCEPT ACCEPT} if the <b>AcceptOnMatch</b>
			property is set to <code>true</code>. The returned decision is 
			{@link spi::Filter#DENY DENY} if the
			<b>AcceptOnMatch</b> property is set to false.
			*/
			FilterDecision decide(const spi::LoggingEventPtr& event) const;
		}; // class LevelMatchFilter
	}; // namespace varia
}; // namespace log4cxx

#endif // _LOG4CXX_VARIA_STRING_MATCH_FILTER_H
