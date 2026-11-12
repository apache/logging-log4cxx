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

#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/spi/errorhandler.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/level.h>

namespace LOG4CXX_NS
{

/**
*  Implementation base class for all appenders.
*
*  This class provides the code for common functionality, such as
*  support for threshold filtering and support for general filters.
* */
class LOG4CXX_EXPORT AppenderSkeleton
	: public Appender
{
	protected:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(AppenderSkeletonPrivate, m_priv)
		AppenderSkeleton(LOG4CXX_PRIVATE_PTR(AppenderSkeletonPrivate) priv);

		/**
		Subclasses of <code>AppenderSkeleton</code> must implement this
		method to perform actual logging. See also AppenderSkeleton::doAppend
		method.
		*/
		virtual void append( const spi::LoggingEventPtr& event ) = 0;

		/**
		* Call the AppenderSkeleton#append method if
		* the level of \c event is not lower than this appender's threshold and
		* no attached spi::Filter indicates \c event is rejected.
		*/
		void doAppendImpl( const spi::LoggingEventPtr& event );
		/**
		* Does no attached filter deny \c event or does an attached filter accept \c event?
		*/
		bool isAccepted(const spi::LoggingEventPtr& event) const;

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(AppenderSkeleton)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(AppenderSkeleton)
		LOG4CXX_CAST_ENTRY(Appender)
		LOG4CXX_CAST_ENTRY(spi::OptionHandler)
		END_LOG4CXX_CAST_MAP()

		AppenderSkeleton(const LayoutPtr& layout = {});
		virtual ~AppenderSkeleton();


		using spi::OptionHandler::activateOptions;
		/**
		\copybrief spi::OptionHandler::activateOptions()

		No action is performed in this implementation.
		*/
		void activateOptions(  ) override;

		/**
		\copybrief spi::OptionHandler::setOption()

		Supported options | Supported values | Default value |
		-------------- | ---------------- | --------------- |
		Name      | {any} | - |
		Threshold | Trace,Debug,Info,Warn,Error,Fatal,Off,All | All |
		*/
		void setOption(const LogString& option, const LogString& value) override;

		/**
		Add \c newFilter to end of the spi::Filter chain.
		*/
		void addFilter(const spi::FilterPtr& newFilter) override;

	public:
		/**
		Clear the spi::Filter chain.
		*/
		void clearFilters() override;

		/** \copydoc Appender::close
		 Calling doAppend() on a closed appender generates one warning on stderr.
		*/
		void close() override;

		/**
		The currently set spi::ErrorHandler for this Appender.
		*/
		const spi::ErrorHandlerPtr getErrorHandler() const;

		/**
		The first spi::Filter in the filter chain for this Appender.
		*/
		spi::FilterPtr getFilter() const override;

		/**
		The first spi::Filter in the filter chain for this Appender.
		*/
		const spi::FilterPtr getFirstFilter() const;

		/**
		The currently set Layout for this appender.
		*/
		LayoutPtr getLayout() const override;

		/**
		The name of this Appender.
		*/
		LogString getName() const override;

		/**
		This appender's current threshold level.
		See the #setThreshold method for the meaning of this option.
		*/
		const LevelPtr getThreshold() const;

		/**
		Is \c level greater than or equal to this appender's threshold?
		*/
		bool isAsSevereAsThreshold(const LevelPtr& level) const;

		/**
		* Call #doAppendImpl after acquiring a lock
		* that prevents other threads from concurrently executing #doAppendImpl.
		*
		* Reimplement this method in your appender if you use a different concurrency control technique.
		* */
		void doAppend( const spi::LoggingEventPtr& event ) override;

		/**
		Use \c newValue as the spi::ErrorHandler for this Appender.
		*/
		void setErrorHandler(const spi::ErrorHandlerPtr& newValue);

		/**
		Use \c newValue as the layout for this appender.
		Note that some appenders have
		their own (fixed) layouts sor do not need one.
		*/
		void setLayout(const LayoutPtr& newValue) override;

		/**
		Use \c newValue for the name of this Appender.
		*/
		void setName(const LogString& newValue) override;


		/**
		Use \c newValue as this appender's threshold level.
		All log events with lower level
		than the appender's threshold level are ignored by the appender.

		In configuration files this option is specified by setting the
		value of the <b>Threshold</b> option to a level
		string, such as "DEBUG", "INFO" and so on.

		The default level is "ALL", the lowest possible level,
		meaning no event is blocked by this threshold.
		*/
		void setThreshold(const LevelPtr& newValue);

}; // class AppenderSkeleton

LOG4CXX_PTR_DEF(AppenderSkeleton);
}  // namespace log4cxx

#endif //_LOG4CXX_APPENDER_SKELETON_H
