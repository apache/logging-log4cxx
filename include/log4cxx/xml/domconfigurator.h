/***************************************************************************
                          domconfigurator.h  -  DOMConfigurator
                             -------------------
    begin                : dim avr 20 2003
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

#ifndef _LOG4CXX_XML_DOM_CONFIGURATOR_H
#define _LOG4CXX_XML_DOM_CONFIGURATOR_H

#include <log4cxx/config.h>
#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectptr.h>
#include <map>
#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/logger.h>

namespace log4cxx
{
	namespace xml
	{
		class AppenderMap
		{
		public:
			AppenderPtr get(const tstring& appenderName);
			void put(const tstring& appenderName, AppenderPtr appender);

		protected:
			std::map<tstring, AppenderPtr> map;
		};

		/**
		Use this class to initialize the log4cxx environment using a DOM tree.

		<p>Sometimes it is useful to see how log4cxx is reading configuration
		files. You can enable log4cxx internal logging by setting the
		<code>debug</code> attribute in the
		<code>log4cxx</code> element. As in
		<pre>
		&lt;log4cxx <b>debug="true"</b>>
		...
		&lt;/log4cxx>
		</pre>

		<p>There are sample XML files included in the package.
		*/
		class DOMConfigurator
		{
		public:
			void doConfigure(const tstring& URL);
			void BuildElement(const tstring& parentTagName, const tstring& tagName);
			void BuildAttribute(const tstring& elementTagName, const tstring& name, const tstring& value);

		private:
			void BuildLog4cxxAttribute(const tstring& name, const tstring& value);
			void BuildAppenderAttribute(const tstring& name, const tstring& value);
			void BuildLayoutAttribute(const tstring& name, const tstring& value);
			void BuildParameterAttribute(const tstring& name, const tstring& value);
			void BuildLoggerAttribute(const tstring& name, const tstring& value);
			void BuildAppenderRefAttribute(const tstring& name, const tstring& value);
			void BuildFilterAttribute(const tstring& name, const tstring& value);
			void BuildLevelAttribute(const tstring& name, const tstring& value);
			void BuildLoggerAdditivity(LoggerPtr& logger, const tstring& additivityValue);
			AppenderPtr BuildAppender(const tstring& className);
			LayoutPtr BuildLayout(const tstring& className);
			spi::FilterPtr BuildFilter(const tstring& className);

			AppenderPtr currentAppender;
			tstring currentAppenderName;
			tstring currentParamName;
			tstring currentParamValue;
			LoggerPtr currentLogger;
			tstring currentAdditivity;
			spi::AppenderAttachablePtr currentAppenderAttachable;
			spi::OptionHandlerPtr currentOptionHandler;

			void * appenderBag;
		};
	}; // namespace xml
}; // namespace log4cxx

#endif // _LOG4CXX_XML_DOM_CONFIGURATOR_H

