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
#include <log4cxx/spi/configurator.h>
#include <log4cxx/file.h>

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
class LOG4CXX_EXPORT DOMConfigurator
	: public spi::Configurator
{
	public:
		~DOMConfigurator();


	public:
		DOMConfigurator();

		DECLARE_LOG4CXX_OBJECT(DOMConfigurator)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(spi::Configurator)
		END_LOG4CXX_CAST_MAP()


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
			, const spi::LoggerRepositoryPtr& repository = spi::LoggerRepositoryPtr()
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


	private:
		//   prevent assignment or copy statements
		DOMConfigurator(const DOMConfigurator&);
		DOMConfigurator& operator=(const DOMConfigurator&);

		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(DOMConfiguratorPrivate, m_priv)
};
LOG4CXX_PTR_DEF(DOMConfigurator);
}  // namespace xml
} // namespace log4cxx

#endif /* LOG4CXX_HAS_DOMCONFIGURATOR */

#endif // _LOG4CXX_XML_DOM_CONFIGURATOR_H
