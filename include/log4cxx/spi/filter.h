/***************************************************************************
                          filter.h  -  class Filter
                             -------------------
    begin                : mer avr 16 2003
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

#ifndef _LOG4CXX_SPI_FILTER_H
#define _LOG4CXX_SPI_FILTER_H

#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/spi/optionhandler.h>

namespace log4cxx
{
	namespace spi
	{
		class Filter;
		typedef helpers::ObjectPtr<Filter> FilterPtr;

		class LoggingEvent;
	
        /**
        Users should extend this class to implement customized logging
        event filtering. Note that Logger and 
        AppenderSkeleton, the parent class of all standard
        appenders, have built-in filtering rules. It is suggested that you
        first use and understand the built-in rules before rushing to write
        your own custom filters.

        <p>This abstract class assumes and also imposes that filters be
        organized in a linear chain. The {@link #decide
        decide(LoggingEvent)} method of each filter is called sequentially,
        in the order of their addition to the chain.

        <p>The {@link #decide decide(LoggingEvent)} method must return one
        of the integer constants #DENY, #NEUTRAL or 
        #ACCEPT.

        <p>If the value #DENY is returned, then the log event is
        dropped immediately without consulting with the remaining
        filters.

        <p>If the value #NEUTRAL is returned, then the next filter
        in the chain is consulted. If there are no more filters in the
        chain, then the log event is logged. Thus, in the presence of no
        filters, the default behaviour is to log all logging events.

        <p>If the value #ACCEPT is returned, then the log
        event is logged without consulting the remaining filters.

        <p>The philosophy of log4cxx filters is largely inspired from the
        Linux ipchains.

        <p>Note that filtering is only supported by the {@link
        xml::DOMConfigurator DOMConfigurator}. 
        */
		class Filter : public virtual OptionHandler,
			public virtual helpers::ObjectImpl
		{
		public:
            /**
            Points to the next filter in the filter chain.
            */
            FilterPtr next;

            enum FilterDecision
            {
            /**
            The log event must be dropped immediately without consulting
			with the remaining filters, if any, in the chain.  */
			DENY = -1,
            /**
            This filter is neutral with respect to the log event. The
            remaining filters, if any, should be consulted for a final decision.
            */
			NEUTRAL = 0,
            /**
            The log event must be logged immediately without consulting with
            the remaining filters, if any, in the chain.
			*/
			ACCEPT = 1,

			};


            /**
            Usually filters options become active when set. We provide a

            default do-nothing implementation for convenience.
            */
            void activateOptions() {}
            void setOption(const tstring& option, const tstring& value) {}

            /**
            <p>If the decision is <code>DENY</code>, then the event will be
            dropped. If the decision is <code>NEUTRAL</code>, then the next
            filter, if any, will be invoked. If the decision is ACCEPT then
            the event will be logged without consulting with other filters in
            the chain.

            @param event The LoggingEvent to decide upon.
            @return The decision of the filter.  */
            virtual int decide(const LoggingEvent& event) = 0;
		};
	};
};

#endif //_LOG4CXX_SPI_FILTER_H
