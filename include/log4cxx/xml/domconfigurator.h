/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/helpers/objectimpl.h>
#include <map>
#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/logger.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/spi/configurator.h>

namespace log4cxx
{
        class File;

        namespace spi
        {
                class LoggerRepository;
                typedef helpers::ObjectPtrT<LoggerRepository> LoggerRepositoryPtr;

                class Filter;
                typedef helpers::ObjectPtrT<Filter> FilterPtr;

                class AppenderAttachable;
                typedef helpers::ObjectPtrT<AppenderAttachable> AppenderAttachablePtr;

                class OptionHandler;
                typedef helpers::ObjectPtrT<OptionHandler> OptionHandlerPtr;
        }

        namespace helpers
        {
                class XMLDOMDocument;
                typedef helpers::ObjectPtrT<XMLDOMDocument> XMLDOMDocumentPtr;

                class XMLDOMElement;
                typedef helpers::ObjectPtrT<XMLDOMElement> XMLDOMElementPtr;
        }

        namespace config
        {
                class PropertySetter;
        }

        namespace rolling
        {
                class RollingPolicy;
                typedef helpers::ObjectPtrT<RollingPolicy> RollingPolicyPtr;

                class TriggeringPolicy;
                typedef helpers::ObjectPtrT<TriggeringPolicy> TriggeringPolicyPtr;
        }



        namespace xml
        {
                class AppenderMap
                {
                public:
                        AppenderPtr get(const LogString& appenderName);
                        void put(const LogString& appenderName, AppenderPtr appender);

                protected:
                        std::map<LogString, AppenderPtr> map;
                };

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
                        virtual public spi::Configurator,
                        virtual public helpers::ObjectImpl
                {
                protected:
                        /**
                        Used internally to parse appenders by IDREF name.
                        */
                        AppenderPtr findAppenderByName(helpers::XMLDOMDocumentPtr doc,
                                const LogString& appenderName);

                        /**
                        Used internally to parse appenders by IDREF element.
                        */
                        AppenderPtr findAppenderByReference(
                                helpers::XMLDOMElementPtr appenderRef);

                        /**
                        Used internally to parse an appender element.
                        */
                        AppenderPtr parseAppender(helpers::XMLDOMElementPtr appenderElement);

                        /**
                        Used internally to parse an {@link spi::ErrorHandler ErrorHandler } element.
                        */
                        void parseErrorHandler(helpers::XMLDOMElementPtr element, AppenderPtr appender);

                        /**
                         Used internally to parse a filter element.
                        */
                        void parseFilters(helpers::XMLDOMElementPtr element,
                           std::vector<log4cxx::spi::FilterPtr>& filters);

                        /**
                        Used internally to parse a logger element.
                        */
                        void parseLogger(helpers::XMLDOMElementPtr loggerElement);

                        /**
                         Used internally to parse the logger factory element.
                        */
                        void parseLoggerFactory(helpers::XMLDOMElementPtr factoryElement);

                        /**
                         Used internally to parse the logger factory element.
                        */
                        log4cxx::rolling::TriggeringPolicyPtr parseTriggeringPolicy(helpers::XMLDOMElementPtr factoryElement);

                        /**
                         Used internally to parse the logger factory element.
                        */
                        log4cxx::rolling::RollingPolicyPtr parseRollingPolicy(helpers::XMLDOMElementPtr factoryElement);

                        /**
                         Used internally to parse the roor category element.
                        */
                        void parseRoot(helpers::XMLDOMElementPtr rootElement);

                        /**
                         Used internally to parse the children of a category element.
                        */
                        void parseChildrenOfLoggerElement(helpers::XMLDOMElementPtr catElement,
                                LoggerPtr logger, bool isRoot);

                        /**
                         Used internally to parse a layout element.
                        */
                        LayoutPtr parseLayout(helpers::XMLDOMElementPtr layout_element);

                        /**
                         Used internally to parse a level  element.
                        */
                        void parseLevel(helpers::XMLDOMElementPtr element,
                                LoggerPtr logger, bool isRoot);

                        void setParameter(helpers::XMLDOMElementPtr elem,
                                config::PropertySetter& propSetter);

                        /**
                         Used internally to configure the log4cxx framework by parsing a DOM
                         tree of XML elements based on <a
                         href="docs/log4j.dtd">log4j.dtd</a>.

                        */
                        void parse(helpers::XMLDOMElementPtr element);

                public:
                        DOMConfigurator();

                        DECLARE_LOG4CXX_OBJECT(DOMConfigurator)
                        BEGIN_LOG4CXX_CAST_MAP()
                                LOG4CXX_CAST_ENTRY(spi::Configurator)
                        END_LOG4CXX_CAST_MAP()

                        DOMConfigurator(log4cxx::helpers::Pool& p);

                        /**
                        A static version of #doConfigure.
                        */
                        static void configure(const std::string& filename);
#if LOG4CXX_HAS_WCHAR_T
                        static void configure(const std::wstring& filename);
#endif
                        /**
                        Like #configureAndWatch(const String& configFilename, long delay)
                        except that the default delay as defined by
                        helpers::FileWatchdog#DEFAULT_DELAY is used.
                        @param configFilename A log4j configuration file in XML format.
                        */
                        static void configureAndWatch(const std::string& configFilename);
#if LOG4CXX_HAS_WCHAR_T
                        static void configureAndWatch(const std::wstring& configFilename);
#endif
                        /**
                        Read the configuration file <code>configFilename</code> if it
                        exists. Moreover, a thread will be created that will periodically
                        check if <code>configFilename</code> has been created or
                        modified. The period is determined by the <code>delay</code>
                        argument. If a change or file creation is detected, then
                        <code>configFilename</code> is read to configure log4cxx.

                        @param configFilename A log4j configuration file in XML format.
                        @param delay The delay in milliseconds to wait between each check.
                        */
                        static void configureAndWatch(const std::string& configFilename,
                                long delay);
#if LOG4CXX_HAS_WCHAR_T
                        static void configureAndWatch(const std::wstring& configFilename,
                                long delay);
#endif

                        /**
                        Interpret the XML file pointed by <code>filename</code> and set up
                        log4cxx accordingly.
                        <p>The configuration is done relative to the hierarchy parameter.
                        @param filename The file to parse.
                        @param repository The hierarchy to operation upon.
                        */
                        void doConfigure(const File& filename,
                                spi::LoggerRepositoryPtr& repository);

                protected:
                        LogString DOMConfigurator::subst(const LogString& value);

                protected:
                        void * appenderBag;

                        helpers::Properties props;
                        spi::LoggerRepositoryPtr repository;
                        spi::LoggerFactoryPtr loggerFactory;

                 private:
                        //   prevent assignment or copy statements
                        DOMConfigurator(const DOMConfigurator&);
                        DOMConfigurator& operator=(const DOMConfigurator&);
                };
        }  // namespace xml
} // namespace log4cxx

#endif // _LOG4CXX_XML_DOM_CONFIGURATOR_H
