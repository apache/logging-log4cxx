/***************************************************************************
      triggeringeventevaluator.cpp  -  class TriggeringEventEvaluator
                             -------------------
    begin                : jeu mai 8 2003
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

#ifndef _LOG4CXX_SPI_TRIGGERING_EVENT_EVALUATOR_H
#define _LOG4CXX_SPI_TRIGGERING_EVENT_EVALUATOR_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	namespace spi
	{
		class TriggeringEventEvaluator;
		typedef helpers::ObjectPtrT<TriggeringEventEvaluator>
			TriggeringEventEvaluatorPtr;

		class LoggingEvent;

		/**
		Implementions of this interface allow certain appenders to decide
		when to perform an appender specific action.

		<p>For example the {@net::SMTPAppender SMTPAppender} sends
		an email when the #isTriggeringEvent method returns
		<code>true</code> and adds the event to an internal buffer when the
		returned result is <code>false</code>.

		*/
 		class TriggeringEventEvaluator : public virtual helpers::Object
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(TriggeringEventEvaluator)
			/**
			Is this the triggering event?
			*/
			virtual bool isTriggeringEvent(const spi::LoggingEvent& event) = 0;
		};
	};
};

#endif // _LOG4CXX_SPI_TRIGGERING_EVENT_EVALUATOR_H
