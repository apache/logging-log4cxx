/***************************************************************************
                                 xlogger.h
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

#include <log4cxx/logger.h>
#include "../xml/xlevel.h"

namespace log4cxx
{
	// Any sub-class of Logger must also have its own implementation of
	// CategoryFactory.
	class XFactory :
		public virtual spi::LoggerFactory,
		public virtual helpers::ObjectImpl
	{
	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(XFactory)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(XFactory)
			LOG4CXX_CAST_ENTRY(spi::LoggerFactory)
		END_LOG4CXX_CAST_MAP()

		XFactory();
		virtual LoggerPtr makeNewLoggerInstance(const String& name);
	};

	typedef helpers::ObjectPtrT<XFactory> XFactoryPtr;

	/**
	A simple example showing Logger sub-classing. It shows the
	minimum steps necessary to implement one's {@link LoggerFactory}.
	Note that sub-classes follow the hierarchy even if its loggers
	belong to different classes.
	*/
	class XLogger : public Logger
	{
	// It's usually a good idea to add a dot suffix to the fully
	// qualified class name. This makes caller localization to work
	// properly even from classes that have almost the same fully
	// qualified class name as XLogger, such as XLogegoryTest.
	static String FQCN;

	// It's enough to instantiate a factory once and for all.
	static XFactoryPtr factory;
	String suffix;

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(XLogger)
		BEGIN_LOG4CXX_CAST_MAP()
			LOG4CXX_CAST_ENTRY(XLogger)
			LOG4CXX_CAST_ENTRY_CHAIN(Logger)
		END_LOG4CXX_CAST_MAP()

		/**
			Just calls the parent constuctor.
		*/
		XLogger(const String& name) : Logger(name) {}

		/**
			Nothing to activate.
		*/
		void activateOptions() {}

		/**
			Overrides the standard debug method by appending the value of
			suffix variable to each message.
		*/
		void debug(const String& message, const char* file=0, int line=-1);

		/**
			We introduce a new printing method in order to support {@link
			XLevel#LETHAL}.  */
		void lethal(const String& message, const char* file=0, int line=-1);

		/**
			We introduce a new printing method in order to support {@link
			XLevel#LETHAL}.  */
		void lethal(const String& message);

		static LoggerPtr getLogger(const String& name);

		static LoggerPtr getLogger(const helpers::Class& clazz);

		String getSuffix() const
			{ return suffix; }

		void setSuffix(const String& suffix)
			{ this->suffix = suffix; }

		/**
			We introduce a new printing method that takes the TRACE level.
		*/
		void trace(const String& message, const char* file=0, int line=-1);

		/**
			We introduce a new printing method that takes the TRACE level.
		*/
		void trace(const String& message);
	};

	typedef helpers::ObjectPtrT<XLogger> XLoggerPtr;
};

#define LOG4CXX_TRACE(logger, message) { \
	if (logger->isEnabledFor(log4cxx::XLevel::TRACE)) {\
	StringBuffer oss; \
	oss << message; \
	logger->trace(oss.str(), __FILE__, __LINE__); }}
