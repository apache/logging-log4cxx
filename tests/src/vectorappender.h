/***************************************************************************
                              vectorappender.h
                             -------------------
    begin                : 2003/12/02
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include <log4cxx/appenderskeleton.h>
#include <vector>
#include <log4cxx/spi/loggingevent.h>

namespace log4cxx
{
	class VectorAppender;
	typedef helpers::ObjectPtrT<VectorAppender> VectorAppenderPtr;


	/**
	An appender that appends logging events to a vector.
	*/
	class VectorAppender : public AppenderSkeleton
	{
	public:
		DECLARE_LOG4CXX_OBJECT(VectorAppender)

		std::vector<spi::LoggingEventPtr> vector;

		/**
		Does nothing.
		*/
		void activateOptions() {}

		/**
		This method is called by the AppenderSkeleton#doAppend
		method.
		*/
		void append(const spi::LoggingEventPtr& event);

		const std::vector<spi::LoggingEventPtr>& getVector() const
			{ return vector; }

		void close();

		bool isClosed() const
			{ return closed; }

		bool requiresLayout() const
			{ return false;	}
	};
};
