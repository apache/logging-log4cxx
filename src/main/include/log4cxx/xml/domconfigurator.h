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

#include <log4cxx/spi/configurator.h>
#include <log4cxx/file.h>

#if LOG4CXX_HAS_DOMCONFIGURATOR

namespace LOG4CXX_NS
{

namespace xml
{

/**
Allows Loggers, Appenders, Layouts and Filters to be set up using directives in a XML format file.

Use Log4cxx internal logging to see values read by Log4cxx.
You can enable Log4cxx internal logging by setting the
<code>debug</code> attribute in the
<code>log4j:configuration</code> element. As in
<pre>
        &lt;log4j:configuration <b>debug="true"</b> xmlns:log4j="http://jakarta.apache.org/log4j/"&gt;
        ...
        &lt;/log4j:configuration&gt;
</pre>

There are sample XML files included in the [Configuration Files](configuration-files.html)
and in the [Log4cxx Examples](examples.html).
*/
class LOG4CXX_EXPORT DOMConfigurator
	: public spi::Configurator
{
	public:
		DOMConfigurator();
		~DOMConfigurator();

		DECLARE_LOG4CXX_OBJECT(DOMConfigurator)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(spi::Configurator)
		END_LOG4CXX_CAST_MAP()

		/** @copydoc spi::Configurator::doConfigure()

		Pre-existing key-value pairs in the property map provided by spi::Configurator::properties()
		are used when expanding ${varname} instances in \c configFileName.
		*/
		spi::ConfigurationStatus doConfigure
			( const File&                     configFileName
			, const spi::LoggerRepositoryPtr& target = {}
			) override;

		/**
		Apply the directives in \c configFileName to the spi::LoggerRepository held by LogManager.

		Pre-existing key-value pairs in the property map provided by spi::Configurator::properties()
		are used when expanding ${varname} instances in \c configFileName.

		<b>The existing configuration is not cleared nor reset.</b>
		If you require a different behavior,
		call {@link spi::LoggerRepository::resetConfiguration resetConfiguration}
		before calling <code>doConfigure</code>.
		*/
		static spi::ConfigurationStatus configure(const File& configFilename);

		/**
		Apply the directives in \c configFileName to the spi::LoggerRepository held by LogManager.

		Pre-existing key-value pairs in the property map provided by spi::Configurator::properties()
		are used when expanding ${varname} instances in \c configFileName.

		<b>The existing configuration is not cleared nor reset.</b>
		If you require a different behavior,
		call {@link spi::LoggerRepository::resetConfiguration resetConfiguration}
		before calling <code>doConfigure</code>.

		A task will be created that periodically checks
		whether \c configFilename has been created or modified.
		A period of log4cxx::helpers::FileWatchdog#DEFAULT_DELAY
		is used if \c delay is not a positive number.
		If a change or file creation is detected,
		then \c configFilename is read to configure Log4cxx.

		The task will be stopped by a LogManager::shutdown call.

		@param configFilename A XML format file.
		@param millisecondDelay The duration to wait between each check.
		*/
		static spi::ConfigurationStatus configureAndWatch
			( const File& configFilename
			, long        millisecondDelay = 0
			);


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
