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

#ifndef _LOG4CXX_XML_DOM_CONFIGURATOR_H
#define _LOG4CXX_XML_DOM_CONFIGURATOR_H

#include <log4cxx/logstring.h>
#include <map>
#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/spi/configurator.h>
#include <log4cxx/helpers/charsetdecoder.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/rolling/triggeringpolicy.h>
#include <log4cxx/rolling/rollingpolicy.h>
#include <log4cxx/file.h>
#include <log4cxx/config/propertysetter.h>

#if LOG4CXX_HAS_DOMCONFIGURATOR

extern "C" {
	struct apr_xml_doc;
	struct apr_xml_elem;
}

namespace LOG4CXX_NS
{

namespace xml
{
class XMLWatchdog;

/**
Use this class to initialize the log4cxx environment using a DOM tree.

<p>Sometimes it is useful to see how log4cxx is reading configuration
files. You can enable log4cxx internal logging by setting the
<code>debug</code> attribute in the
<code>log4cxx</code> element. As in
<pre>
        &lt;log4j:configuration <b>debug="true"</b> xmlns:log4j="http://jakarta.apache.org/log4j/">
        ...
        &lt;/log4j:configuration>
</pre>

<p>There are sample XML files included in the package.
*/
class LOG4CXX_EXPORT DOMConfigurator :
	virtual public spi::Configurator
{
	public:
		~DOMConfigurator();

	protected:
		typedef std::map<LogString, AppenderPtr> AppenderMap;
		/**
		Used internally to parse appenders by IDREF name.
		*/
		AppenderPtr findAppenderByName(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* elem,
			apr_xml_doc* doc,
			const LogString& appenderName,
			AppenderMap& appenders);

		/**
		Used internally to parse appenders by IDREF element.
		*/
		AppenderPtr findAppenderByReference(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* appenderRef,
			apr_xml_doc* doc,
			AppenderMap& appenders);

		/**
		Used internally to parse an appender element.
		*/
		AppenderPtr parseAppender(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* appenderElement,
			apr_xml_doc* doc,
			AppenderMap& appenders);

		/**
		Used internally to parse an {@link spi::ErrorHandler ErrorHandler } element.
		*/
		void parseErrorHandler(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* element,
			AppenderPtr& appender,
			apr_xml_doc* doc,
			AppenderMap& appenders);

		/**
		 Used internally to parse a filter element.
		*/
		void parseFilters(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* element,
			std::vector<LOG4CXX_NS::spi::FilterPtr>& filters);

		/**
		Used internally to parse a logger element.
		*/
		void parseLogger(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* loggerElement,
			apr_xml_doc* doc,
			AppenderMap& appenders);

		/**
		 Used internally to parse the logger factory element.
		*/
		void parseLoggerFactory(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* factoryElement);

		/**
		 Used internally to parse the logger factory element.
		*/
		LOG4CXX_NS::helpers::ObjectPtr parseTriggeringPolicy(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* factoryElement);

		/**
		 Used internally to parse the logger factory element.
		*/
		LOG4CXX_NS::rolling::RollingPolicyPtr parseRollingPolicy(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* factoryElement);

		/**
		 Used internally to parse the root logger element.
		*/
		void parseRoot(LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* rootElement, apr_xml_doc* doc, AppenderMap& appenders);

		/**
		 Used internally to parse the children of a logger element.
		*/
		void parseChildrenOfLoggerElement(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* catElement,
			LoggerPtr logger, bool isRoot,
			apr_xml_doc* doc,
			AppenderMap& appenders );

		/**
		 Used internally to parse a layout element.
		*/
		LayoutPtr parseLayout(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* layout_element);

		/**
		 Used internally to parse a level  element.
		*/
		void parseLevel(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* element,
			LoggerPtr logger, bool isRoot);

		void setParameter(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* elem,
			LOG4CXX_NS::config::PropertySetter& propSetter);

		/**
		 Used internally to configure the log4cxx framework from
		 an in-memory representation of an XML document.
		*/
		void parse(
			LOG4CXX_NS::helpers::Pool& p,
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem* element,
			apr_xml_doc* doc,
			AppenderMap& appenders);

	public:
		DOMConfigurator();

		DECLARE_LOG4CXX_OBJECT(DOMConfigurator)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(spi::Configurator)
		END_LOG4CXX_CAST_MAP()

		DOMConfigurator(LOG4CXX_NS::helpers::Pool& p);

#if LOG4CXX_ABI_VERSION <= 15
		/**
		A static version of #doConfigure.
		*/
		static spi::ConfigurationStatus configure(const char* filename) { return configure(std::string(filename)); }
		/**
		A static version of #doConfigure.
		*/
		static spi::ConfigurationStatus configure(const std::string& filename);
#if LOG4CXX_WCHAR_T_API
		/**
		A static version of #doConfigure.
		*/
		static spi::ConfigurationStatus configure(const wchar_t* filename) { return configure(std::wstring(filename)); }
		/**
		A static version of #doConfigure.
		*/
		static spi::ConfigurationStatus configure(const std::wstring& filename);
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
		/**
		A static version of #doConfigure.
		*/
		static spi::ConfigurationStatus configure(const std::basic_string<UniChar>& filename);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		A static version of #doConfigure.
		*/
		static spi::ConfigurationStatus configure(const CFStringRef& filename);
#endif
		/**
		Like #configureAndWatch(const File& filename, long delay)
		except that the default delay as defined by
		log4cxx::helpers::FileWatchdog#DEFAULT_DELAY is used.
		@param configFilename A configuration file in XML format.
		*/
		static spi::ConfigurationStatus configureAndWatch(const std::string& configFilename);
#if LOG4CXX_WCHAR_T_API
		/**
		Like #configureAndWatch(const File& filename, long delay)
		except that the default delay as defined by
		log4cxx::helpers::FileWatchdog#DEFAULT_DELAY is used.
		@param configFilename A configuration file in XML format.
		*/
		static spi::ConfigurationStatus configureAndWatch(const std::wstring& configFilename);
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
		/**
		Like #configureAndWatch(const File& filename, long delay)
		except that the default delay as defined by
		log4cxx::helpers::FileWatchdog#DEFAULT_DELAY is used.
		@param configFilename A configuration file in XML format.
		*/
		static spi::ConfigurationStatus configureAndWatch(const std::basic_string<UniChar>& configFilename);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Like #configureAndWatch(const File& filename, long delay)
		except that the default delay as defined by
		log4cxx::helpers::FileWatchdog#DEFAULT_DELAY is used.
		@param configFilename A configuration file in XML format.
		*/
		static spi::ConfigurationStatus configureAndWatch(const CFStringRef& configFilename);
#endif
		/**
		Read the configuration file <code>configFilename</code> if it
		exists. Moreover, a thread will be created that will periodically
		check if <code>configFilename</code> has been created or
		modified. The period is determined by the <code>delay</code>
		argument. If a change or file creation is detected, then
		<code>configFilename</code> is read to configure log4cxx.

		The thread will be stopped by a LogManager::shutdown call.

		@param configFilename A configuration file in XML format.
		@param delay The delay in milliseconds to wait between each check.
		*/
		static spi::ConfigurationStatus configureAndWatch(const std::string& configFilename,
			long delay);
#if LOG4CXX_WCHAR_T_API
		/**
		Refer #configureAndWatch(const File& filename, long delay)
		*/
		static spi::ConfigurationStatus configureAndWatch(const std::wstring& configFilename,
			long delay);
#endif
#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
		/**
		Refer #configureAndWatch(const File& filename, long delay)
		*/
		static spi::ConfigurationStatus configureAndWatch(const std::basic_string<UniChar>& configFilename,
			long delay);
#endif
#if LOG4CXX_CFSTRING_API
		/**
		Refer #configureAndWatch(const File& filename, long delay)
		*/
		static spi::ConfigurationStatus configureAndWatch(const CFStringRef& configFilename,
			long delay);
#endif
#endif // LOG4CXX_ABI_VERSION <= 15

		/**
		Interpret \c filename as an XML file and set up Log4cxx accordingly.
		If \c repository is not provided,
		the spi::LoggerRepository held by LogManager is used.
		<b>The existing configuration is not cleared nor reset.</b>
		If you require a different behavior,
		call {@link spi::LoggerRepository::resetConfiguration resetConfiguration}
		before calling <code>doConfigure</code>.

		@param filename The file to parse.
		@param repository Where the Logger instances reside.
		*/
		spi::ConfigurationStatus doConfigure
			( const File&                     filename
#if LOG4CXX_ABI_VERSION <= 15
			, spi::LoggerRepositoryPtr        repository
#else
			, const spi::LoggerRepositoryPtr& repository = spi::LoggerRepositoryPtr()
#endif
			) override;

		/**
		Read configuration options from \c configFilename.
		Stores Logger instances in the spi::LoggerRepository held by LogManager.
		*/
		static spi::ConfigurationStatus configure(const File& configFilename);

		/**
		Read configuration options from \c configFilename (if it exists).
		A thread will be created that periodically checks
		whether \c configFilename has been created or modified.
		A period of log4cxx::helpers::FileWatchdog#DEFAULT_DELAY
		is used if \c delay is not a positive number.
		If a change or file creation is detected,
		then \c configFilename is read to configure Log4cxx.

		The thread will be stopped by a LogManager::shutdown call.

		@param configFilename A XML format file.
		@param delay The delay in milliseconds to wait between each check.
		*/
		static spi::ConfigurationStatus configureAndWatch(const File& configFilename, long delay = 0);

	protected:
		static LogString getAttribute(
			LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
			apr_xml_elem*,
			const std::string& attrName);

		LogString subst(const LogString& value);

	private:
		//   prevent assignment or copy statements
		DOMConfigurator(const DOMConfigurator&);
		DOMConfigurator& operator=(const DOMConfigurator&);
		static XMLWatchdog* xdog;

		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(DOMConfiguratorPrivate, m_priv)
};
LOG4CXX_PTR_DEF(DOMConfigurator);
}  // namespace xml
} // namespace log4cxx

#endif /* LOG4CXX_HAS_DOMCONFIGURATOR */

#endif // _LOG4CXX_XML_DOM_CONFIGURATOR_H
