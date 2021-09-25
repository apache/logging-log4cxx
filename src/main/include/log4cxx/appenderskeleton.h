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

#ifndef _LOG4CXX_APPENDER_SKELETON_H
#define _LOG4CXX_APPENDER_SKELETON_H

#if defined(_MSC_VER)
	#pragma warning ( push )
	#pragma warning ( disable: 4231 4251 4275 4786 )
#endif


#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/spi/errorhandler.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/level.h>

namespace log4cxx
{
namespace priv
{
struct AppenderSkeletonPrivate;
}

/**
*  Implementation base class for all appenders.
*
*  This class provides the code for common functionality, such as
*  support for threshold filtering and support for general filters.
* */
class LOG4CXX_EXPORT AppenderSkeleton :
	public virtual Appender,
	public virtual helpers::Object
{
	protected:
		AppenderSkeleton( std::unique_ptr<priv::AppenderSkeletonPrivate> priv );

		/**
		Subclasses of <code>AppenderSkeleton</code> should implement this
		method to perform actual logging. See also AppenderSkeleton::doAppend
		method.
		*/
		virtual void append(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& p) = 0;

		void doAppendImpl(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& pool);

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(AppenderSkeleton)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(AppenderSkeleton)
		LOG4CXX_CAST_ENTRY(Appender)
		LOG4CXX_CAST_ENTRY(spi::OptionHandler)
		END_LOG4CXX_CAST_MAP()

		AppenderSkeleton();
		AppenderSkeleton(const LayoutPtr& layout);
		virtual ~AppenderSkeleton();

		/**
		Finalize this appender by calling the derived class'
		<code>close</code> method.
		*/
		void finalize();

		/**
		Derived appenders should override this method if option structure
		requires it.
		*/
		virtual void activateOptions(log4cxx::helpers::Pool& /* pool */) {}
		virtual void setOption(const LogString& option, const LogString& value);

		/**
		Add a filter to end of the filter list.
		*/
		void addFilter(const spi::FilterPtr newFilter) ;

	public:
		/**
		Clear the filters chain.
		*/
		void clearFilters();

		/**
		Return the currently set spi::ErrorHandler for this
		Appender.
		*/
		const spi::ErrorHandlerPtr getErrorHandler() const;

		/**
		Returns the head Filter.
		*/
		spi::FilterPtr getFilter() const;

		/**
		Return the first filter in the filter chain for this
		Appender. The return value may be <code>nullptr</code> if no is
		filter is set.
		*/
		const spi::FilterPtr getFirstFilter() const;

		/**
		Returns the layout of this appender. The value may be nullptr.
		*/
		LayoutPtr getLayout() const;


		/**
		Returns the name of this Appender.
		*/
		LogString getName() const;

		/**
		Returns this appenders threshold level. See the #setThreshold
		method for the meaning of this option.
		*/
		const LevelPtr getThreshold() const;

		/**
		Check whether the message level is below the appender's
		threshold. If there is no threshold set, then the return value is
		always <code>true</code>.
		*/
		bool isAsSevereAsThreshold(const LevelPtr& level) const;


		/**
		* This method performs threshold checks and invokes filters before
		* delegating actual logging to the subclasses specific
		* AppenderSkeleton#append method.
		* */
		virtual void doAppend(const spi::LoggingEventPtr& event, log4cxx::helpers::Pool& pool);

		/**
		Set the {@link spi::ErrorHandler ErrorHandler} for this Appender.
		*/
		void setErrorHandler(const spi::ErrorHandlerPtr eh);

		/**
		Set the layout for this appender. Note that some appenders have
		their own (fixed) layouts or do not use one. For example, the
		{@link net::SocketAppender SocketAppender} ignores the layout set
		here.
		*/
		void setLayout(const LayoutPtr layout1);

		/**
		Set the name of this Appender.
		*/
		void setName(const LogString& name1);


		/**
		Set the threshold level. All log events with lower level
		than the threshold level are ignored by the appender.

		<p>In configuration files this option is specified by setting the
		value of the <b>Threshold</b> option to a level
		string, such as "DEBUG", "INFO" and so on.
		*/
		void setThreshold(const LevelPtr& threshold);

protected:
		std::unique_ptr<priv::AppenderSkeletonPrivate> m_priv;

}; // class AppenderSkeleton
}  // namespace log4cxx

#if defined(_MSC_VER)
	#pragma warning ( pop )
#endif


#endif //_LOG4CXX_APPENDER_SKELETON_H
