/***************************************************************************
                          stringmatchfilter.h  -  class StringMatchFilter
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

#ifndef _LOG4CXX_VARIA_STRING_MATCH_FILTER_H
#define _LOG4CXX_VARIA_STRING_MATCH_FILTER_H

#include <log4cxx/spi/filter.h>

namespace log4cxx
{
	namespace spi
	{
		class LoggingEvent;
	};
	
	namespace varia
	{
		/**
		This is a very simple filter based on string matching.

		<p>The filter admits two options <b>StringToMatch</b> and
		<b>AcceptOnMatch</b>. If there is a match between the value of the
		StringToMatch option and the message of the {@link spi::LoggingEvent 
		LoggingEvent}, then the #decide method returns 
		{@link spi::Filter#ACCEPT ACCEPT} if the <b>AcceptOnMatch</b> option
		value is true, if it is false then {@link spi::Filter#DENY DENY} is 
		returned. If there is no match, {@link spi::Filter#NEUTRAL NEUTRAL}
		is returned.

		<p>See configuration files <a
		href="../xml/doc-files/test6.xml">test6.xml</a>, <a
		href="../xml/doc-files/test7.xml">test7.xml</a>, <a
		href="../xml/doc-files/test8.xml">test8.xml</a>, <a
		href="../xml/doc-files/test9.xml">test9.xml</a>, and <a
		href="../xml/doc-files/test10.xml">test10.xml</a> for examples of
		seeting up a <code>StringMatchFilter</code>.
		*/
		class StringMatchFilter : public spi::Filter
		{
		private:
			static tstring STRING_TO_MATCH_OPTION;
			static tstring ACCEPT_ON_MATCH_OPTION;

			bool acceptOnMatch;
			tstring stringToMatch;

		public:
			typedef spi::Filter BASE_CLASS;
			DECLARE_LOG4CXX_OBJECT(StringMatchFilter)
			BEGIN_LOG4CXX_INTERFACE_MAP()
				LOG4CXX_INTERFACE_ENTRY(StringMatchFilter)
				LOG4CXX_INTERFACE_ENTRY_CHAIN(BASE_CLASS)
			END_LOG4CXX_INTERFACE_MAP()

			StringMatchFilter();

			/**
			Set options
			*/
			virtual void setOption(const tstring& option,
				const tstring& value);

			inline void setStringToMatch(const tstring& stringToMatch)
				{ this->stringToMatch = stringToMatch; }

			inline const tstring& getStringToMatch() const
				{ return stringToMatch; }

			inline void setAcceptOnMatch(bool acceptOnMatch)
				{ this->acceptOnMatch = acceptOnMatch; }

			inline bool getAcceptOnMatch() const
				{ return acceptOnMatch; }

			/**
			Returns {@link spi::Filter#NEUTRAL NEUTRAL} 
			is there is no string match.
			*/
			int decide(const spi::LoggingEvent& event);
}; // class StringMatchFilter
	}; // namespace varia
}; // namespace log4cxx

#endif // _LOG4CXX_VARIA_STRING_MATCH_FILTER_H
