/***************************************************************************
                          denyallfilter.h  -  class DenyAllFilter
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

#ifndef _LOG4CXX_VARIA_DENY_ALL_FILTER_H
#define _LOG4CXX_VARIA_DENY_ALL_FILTER_H

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
		This filter drops all logging events.
		<p>You can add this filter to the end of a filter chain to
		switch from the default "accept all unless instructed otherwise"
		filtering behaviour to a "deny all unless instructed otherwise"
		behaviour.
		*/
		class DenyAllFilter;
		typedef helpers::ObjectPtrT<DenyAllFilter> DenyAllFilterPtr;

		class DenyAllFilter : public spi::Filter
		{
		public:
			typedef spi::Filter BASE_CLASS;
			DECLARE_LOG4CXX_OBJECT(DenyAllFilter)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(DenyAllFilter)
				LOG4CXX_CAST_ENTRY_CHAIN(BASE_CLASS)
			END_LOG4CXX_CAST_MAP()

			/**
			Always returns the integer constant {@link spi::Filter#DENY DENY}
			regardless of the {@link spi::LoggingEvent LoggingEvent} parameter.
			@param event The LoggingEvent to filter.
			@return Always returns {@link spi::Filter#DENY DENY}.
			*/
			FilterDecision decide(const spi::LoggingEvent& event)
				{ return spi::Filter::DENY; }
		}; // class DenyAllFilter
	}; // namespace varia
}; // namespace log4cxx

#endif // _LOG4CXX_VARIA_DENY_ALL_FILTER_H
