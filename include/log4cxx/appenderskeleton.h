/***************************************************************************
                          appenderskeleton.h  -  class AppenderSkeleton
                             -------------------
    begin                : mar avr 15 2003
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

#ifndef _LOG4CXX_APPENDER_SKELETON_H
#define _LOG4CXX_APPENDER_SKELETON_H

#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/spi/errorhandler.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/level.h>

namespace log4cxx
{
	/**
	*  Implementation base class for all appenders.
	*
	*  This class provides the code for common functionality, such as
	*  support for threshold filtering and support for general filters.
	* */
	class LOG4CXX_EXPORT AppenderSkeleton :
		public virtual Appender,
		public virtual helpers::ObjectImpl
	{
	protected:
		/** The layout variable does not need to be set if the appender
		implementation has its own layout. */
		LayoutPtr layout;

		/** Appenders are named. */
		String name;

		/**
		There is no level threshold filtering by default.  */
		LevelPtr threshold;

		/**
		It is assumed and enforced that errorHandler is never null.
		*/
		spi::ErrorHandlerPtr errorHandler;

		/** The first filter in the filter chain. Set to <code>null</code>
		initially. */
		spi::FilterPtr headFilter;
	
		/** The last filter in the filter chain. */
		spi::FilterPtr tailFilter;

		/**
		Is this appender closed?
		*/
		bool closed;

	public:
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(Appender)
			LOG4CXX_CAST_ENTRY(spi::OptionHandler)
		END_LOG4CXX_CAST_MAP()

		AppenderSkeleton();

		/**
		Finalize this appender by calling the derived class'
		<code>close</code> method.
		*/
		void finalize();

	public:
		/**
		Derived appenders should override this method if option structure
		requires it.
		*/
		void activateOptions() {}
		void setOption(const String& name, const String& value) {}

		/**
		Add a filter to end of the filter list.
		*/
	public:
		void addFilter(spi::FilterPtr newFilter) ;

		/**
		Subclasses of <code>AppenderSkeleton</code> should implement this
		method to perform actual logging. See also AppenderSkeleton::doAppend
		method.
		*/
	protected:
		virtual void append(const spi::LoggingEventPtr& event) = 0;

		/**
		Clear the filters chain.
		*/
	public:
		void clearFilters();

		/**
		Return the currently set spi::ErrorHandler for this
		Appender.
		*/
	public:
		spi::ErrorHandlerPtr getErrorHandler() { return errorHandler; }

		/**
		Returns the head Filter.
		*/
	public:
		spi::FilterPtr getFilter() { return headFilter; }

		/**
		Return the first filter in the filter chain for this
		Appender. The return value may be <code>0</code> if no is
		filter is set.
		*/
	public:
		spi::FilterPtr getFirstFilter() { return headFilter; }

		/**
		Returns the layout of this appender. The value may be 0.
		*/
	public:
		LayoutPtr getLayout() { return layout; }


		/**
		Returns the name of this Appender.
		*/
	public:
		const String& getName() { return name; }

		/**
		Returns this appenders threshold level. See the #setThreshold
		method for the meaning of this option.
		*/
	public:
		const LevelPtr& getThreshold() { return threshold; }

		/**
		Check whether the message level is below the appender's
		threshold. If there is no threshold set, then the return value is
		always <code>true</code>.
		*/
	public:
		bool isAsSevereAsThreshold(LevelPtr level);


		/**
		* This method performs threshold checks and invokes filters before
		* delegating actual logging to the subclasses specific
		* AppenderSkeleton#append method.
		* */
	public:
		void doAppend(const spi::LoggingEventPtr& event);

		/**
		Set the {@link spi::ErrorHandler ErrorHandler} for this Appender.
		*/
	public:
		void setErrorHandler(spi::ErrorHandlerPtr eh);

		/**
		Set the layout for this appender. Note that some appenders have
		their own (fixed) layouts or do not use one. For example, the
		{@link net::SocketAppender SocketAppender} ignores the layout set
		here.
		*/
	public:
		void setLayout(LayoutPtr layout) { this->layout = layout; }

		/**
		Set the name of this Appender.
		*/
	public:
		void setName(const String& name) { this->name = name; }


		/**
		Set the threshold level. All log events with lower level
		than the threshold level are ignored by the appender.

		<p>In configuration files this option is specified by setting the
		value of the <b>Threshold</b> option to a level
		string, such as "DEBUG", "INFO" and so on.
		*/
	public:
		void setThreshold(const LevelPtr& threshold);
	}; // class AppenderSkeleton
}; // namespace log4cxx

#endif //_LOG4CXX_APPENDER_SKELETON_H
