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

#include <log4cxx/logstring.h>
#include <log4cxx/private/log4cxx_private.h>


#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/appender.h>
#include <log4cxx/layout.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/level.h>
#include <log4cxx/spi/filter.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/loader.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/config/propertysetter.h>
#include <log4cxx/spi/errorhandler.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/defaultloggerfactory.h>
#include <log4cxx/helpers/filewatchdog.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/pool.h>
#include <sstream>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/rolling/filterbasedtriggeringpolicy.h>
#include <apr_xml.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/charsetdecoder.h>

using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::config;
using namespace log4cxx::rolling;


class XMLWatchdog  : public FileWatchdog
{
public:
        XMLWatchdog(const LogString& filename) : FileWatchdog(filename)
        {
        }

        /**
        Call DOMConfigurator#doConfigure with the
        <code>filename</code> to reconfigure log4cxx.
        */
        void doOnChange()
        {
                DOMConfigurator().doConfigure(file,
                        LogManager::getLoggerRepository());
        }
};


IMPLEMENT_LOG4CXX_OBJECT(DOMConfigurator)

#define CONFIGURATION_TAG "log4j:configuration"
#define OLD_CONFIGURATION_TAG "configuration"
#define APPENDER_TAG "appender"
#define APPENDER_REF_TAG "appender-ref"
#define PARAM_TAG "param"
#define LAYOUT_TAG "layout"
#define ROLLING_POLICY_TAG "rollingPolicy"
#define TRIGGERING_POLICY_TAG "triggeringPolicy"
#define CATEGORY "category"
#define LOGGER "logger"
#define LOGGER_REF "logger-ref"
#define CATEGORY_FACTORY_TAG "categoryFactory"
#define NAME_ATTR "name"
#define CLASS_ATTR "class"
#define VALUE_ATTR "value"
#define ROOT_TAG "root"
#define ROOT_REF "root-ref"
#define LEVEL_TAG "level"
#define PRIORITY_TAG "priority"
#define FILTER_TAG "filter"
#define ERROR_HANDLER_TAG "errorHandler"
#define REF_ATTR "ref"
#define ADDITIVITY_ATTR "additivity"
#define THRESHOLD_ATTR "threshold"
#define CONFIG_DEBUG_ATTR "configDebug"
#define INTERNAL_DEBUG_ATTR "debug"

DOMConfigurator::DOMConfigurator()
   : props(), repository() {
}


/**
Used internally to parse appenders by IDREF name.
*/
AppenderPtr DOMConfigurator::findAppenderByName(apr_xml_elem* element,
                                                apr_xml_doc* doc,
                                                const LogString& appenderName,
                                                AppenderMap& appenders) {
    AppenderPtr appender;
    std::string tagName(element->name);
    if (tagName == APPENDER_TAG) {
        if (appenderName == getAttribute(element, NAME_ATTR)) {
              appender = parseAppender(element, doc, appenders);
        }
    }
    if (element->first_child && !appender) {
         appender = findAppenderByName(element->first_child, doc, appenderName, appenders);
    }
    if (element->next && !appender) {
        appender = findAppenderByName(element->next, doc, appenderName, appenders);
    }
    return appender;
}

/**
 Used internally to parse appenders by IDREF element.
*/
AppenderPtr DOMConfigurator::findAppenderByReference(apr_xml_elem* appenderRef,
                                                     apr_xml_doc* doc,
                                                     AppenderMap& appenders)
{
        LogString appenderName(subst(getAttribute(appenderRef, REF_ATTR)));
        AppenderMap::const_iterator match = appenders.find(appenderName);
        AppenderPtr appender;
        if (match != appenders.end()) {
            appender = match->second;
        } else if (doc) {
            appender = findAppenderByName(doc->root, doc, appenderName, appenders);
            if (appender) {
                appenders.insert(AppenderMap::value_type(appenderName, appender));
            }
        }
        if (!appender) {
                 LogLog::error(LOG4CXX_STR("No appender named [")+
                                appenderName+LOG4CXX_STR("] could be found."));
        }
        return appender;
}

/**
Used internally to parse an appender element.
*/
AppenderPtr DOMConfigurator::parseAppender(apr_xml_elem* appenderElement,
                                           apr_xml_doc* doc,
                                           AppenderMap& appenders)
{

    LogString className(subst(getAttribute(appenderElement, CLASS_ATTR)));
    LogLog::debug(LOG4CXX_STR("Class name: [") + className+LOG4CXX_STR("]"));
    try
        {
                ObjectPtr instance = Loader::loadClass(className).newInstance();
                AppenderPtr appender = instance;
                PropertySetter propSetter(appender);

                appender->setName(subst(getAttribute(appenderElement, NAME_ATTR)));

                for(apr_xml_elem* currentElement = appenderElement->first_child;
                     currentElement;
                     currentElement = currentElement->next) {

                                std::string tagName(currentElement->name);

                                // Parse appender parameters
                                if (tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                                // Set appender layout
                                else if (tagName == LAYOUT_TAG)
                                {
                                        appender->setLayout(parseLayout(currentElement));
                                }
                                // Add filters
                                else if (tagName == FILTER_TAG)
                                {
                                        std::vector<log4cxx::spi::FilterPtr> filters;
                                        parseFilters(currentElement, filters);
                                        for(std::vector<log4cxx::spi::FilterPtr>::iterator iter = filters.begin();
                                            iter != filters.end();
                                            iter++) {
                                            appender->addFilter(*iter);
                                        }
                                }
                                else if (tagName == ERROR_HANDLER_TAG)
                                {
                                        parseErrorHandler(currentElement, appender, doc, appenders);
                                }
                                else if (tagName == ROLLING_POLICY_TAG)
                                {
                                        RollingPolicyPtr rollPolicy(parseRollingPolicy(currentElement));
                                        RollingFileAppenderPtr rfa(appender);
                                        if (rfa != NULL) {
                                           rfa->setRollingPolicy(rollPolicy);
                                        }
                                }
                                else if (tagName == TRIGGERING_POLICY_TAG)
                                {
                                        TriggeringPolicyPtr triggerPolicy(parseTriggeringPolicy(currentElement));
                                        RollingFileAppenderPtr rfa(appender);
                                        if (rfa != NULL) {
                                           rfa->setTriggeringPolicy(triggerPolicy);
                                        }
                                }
                                else if (tagName == APPENDER_REF_TAG)
                                {
                                        LogString refName = subst(getAttribute(currentElement, REF_ATTR));
                                        if(appender->instanceof(AppenderAttachable::getStaticClass()))
                                        {
                                                AppenderAttachablePtr aa = appender;
                                                LogLog::debug(LOG4CXX_STR("Attaching appender named [")+
                                                        refName+LOG4CXX_STR("] to appender named [")+
                                                        appender->getName()+LOG4CXX_STR("]."));
                                                aa->addAppender(findAppenderByReference(currentElement, doc, appenders));
                                        }
                                        else
                                        {
                                                LogLog::error(LOG4CXX_STR("Requesting attachment of appender named [")+
                                                        refName+ LOG4CXX_STR("] to appender named [")+ appender->getName()+
                                                        LOG4CXX_STR("] which does not implement AppenderAttachable."));
                                        }
                                }
                }
                Pool p;
                propSetter.activate(p);
                return appender;
    }
    /* Yes, it's ugly.  But all of these exceptions point to the same
        problem: we can't create an Appender */
    catch (Exception& oops)
        {
                LogLog::error(LOG4CXX_STR("Could not create an Appender. Reported error follows."),
                        oops);
                return 0;
    }
}

/**
Used internally to parse an {@link ErrorHandler} element.
*/
void DOMConfigurator::parseErrorHandler(apr_xml_elem* element, 
                                        AppenderPtr& appender,
                                        apr_xml_doc* doc,
                                        AppenderMap& appenders)
{
    ErrorHandlerPtr eh = OptionConverter::instantiateByClassName(
                subst(getAttribute(element, CLASS_ATTR)),
                ErrorHandler::getStaticClass(),
                0);

    if(eh != 0)
        {
                eh->setAppender(appender);

                PropertySetter propSetter(eh);

                for (apr_xml_elem* currentElement = element->first_child;
                     currentElement;
                     currentElement = currentElement->next) {
                                std::string tagName(currentElement->name);
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                                else if(tagName == APPENDER_REF_TAG)
                                {
                                        eh->setBackupAppender(findAppenderByReference(currentElement, doc, appenders));
                                }
                                else if(tagName == LOGGER_REF)
                                {
                                        LogString loggerName(getAttribute(currentElement, REF_ATTR));
                                        LoggerPtr logger = repository->getLogger(loggerName, loggerFactory);
                                        eh->setLogger(logger);
                                }
                                else if(tagName == ROOT_REF)
                                {
                                        LoggerPtr root = repository->getRootLogger();
                                        eh->setLogger(root);
                                }
                }
                Pool p;
                propSetter.activate(p);
//                appender->setErrorHandler(eh);
    }
}

/**
 Used internally to parse a filter element.
*/
void DOMConfigurator::parseFilters(apr_xml_elem* element, std::vector<log4cxx::spi::FilterPtr>& filters)
{
        LogString clazz = subst(getAttribute(element, CLASS_ATTR));
        FilterPtr filter = OptionConverter::instantiateByClassName(clazz,
                Filter::getStaticClass(), 0);

        if(filter != 0)
        {
                PropertySetter propSetter(filter);

                for (apr_xml_elem* currentElement = element->first_child;
                     currentElement;
                     currentElement = currentElement->next)
                {
                                std::string tagName(currentElement->name);
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                }
                Pool p;
                propSetter.activate(p);
                filters.push_back(filter);
        }
}

/**
Used internally to parse an category or logger element.
*/
void DOMConfigurator::parseLogger(apr_xml_elem* loggerElement, 
                                  apr_xml_doc* doc,
                                  AppenderMap& appenders)
{
        // Create a new Logger object from the <category> element.
        LogString loggerName = subst(getAttribute(loggerElement, NAME_ATTR));

        LogLog::debug(LOG4CXX_STR("Retreiving an instance of Logger."));
        LoggerPtr logger = repository->getLogger(loggerName, loggerFactory);

        // Setting up a logger needs to be an atomic operation, in order
        // to protect potential log operations while logger
        // configuration is in progress.
        synchronized sync(logger->getMutex());
        bool additivity = OptionConverter::toBoolean(
                subst(getAttribute(loggerElement, ADDITIVITY_ATTR)),
                true);

        LogLog::debug(LOG4CXX_STR("Setting [")+logger->getName()+LOG4CXX_STR("] additivity to [")+
                (additivity ? LogString(LOG4CXX_STR("true")) : LogString(LOG4CXX_STR("false")))+LOG4CXX_STR("]."));
        logger->setAdditivity(additivity);
        parseChildrenOfLoggerElement(loggerElement, logger, false, doc, appenders);
}

/**
 Used internally to parse the logger factory element.
*/
void DOMConfigurator::parseLoggerFactory(apr_xml_elem* factoryElement)
{
        LogString className(subst(getAttribute(factoryElement, CLASS_ATTR)));

        if(className.empty())
        {
                LogLog::error(LOG4CXX_STR("Logger Factory tag class attribute not found."));
                LogLog::debug(LOG4CXX_STR("No Logger Factory configured."));
        }
        else
        {
                LogLog::debug(LOG4CXX_STR("Desired logger factory: [")+className+LOG4CXX_STR("]"));
                loggerFactory = OptionConverter::instantiateByClassName(
                        className,
                        LoggerFactory::getStaticClass(),
                        0);
                PropertySetter propSetter(loggerFactory);

                for (apr_xml_elem* currentElement = factoryElement->first_child;
                     currentElement;
                     currentElement = currentElement->next) {
                     std::string tagName(currentElement->name);
                     if (tagName == PARAM_TAG) {
                            setParameter(currentElement, propSetter);
                    }
                }
        }
}

/**
 Used internally to parse the root logger element.
*/
void DOMConfigurator::parseRoot(apr_xml_elem* rootElement, apr_xml_doc* doc, AppenderMap& appenders)
{
        LoggerPtr root = repository->getRootLogger();
        // logger configuration needs to be atomic
        synchronized sync(root->getMutex());
        parseChildrenOfLoggerElement(rootElement, root, true, doc, appenders);
}

/**
 Used internally to parse the children of a logger element.
*/
void DOMConfigurator::parseChildrenOfLoggerElement(
        apr_xml_elem* loggerElement, LoggerPtr logger, bool isRoot,
        apr_xml_doc* doc, AppenderMap& appenders)
{

    PropertySetter propSetter(logger);

    // Remove all existing appenders from logger. They will be
    // reconstructed if need be.
    logger->removeAllAppenders();


    for (apr_xml_elem* currentElement = loggerElement->first_child;
         currentElement;
         currentElement = currentElement->next) {
                        std::string tagName(currentElement->name);

                        if (tagName == APPENDER_REF_TAG)
                        {
                                AppenderPtr appender = findAppenderByReference(currentElement, doc, appenders);
                                LogString refName =  subst(getAttribute(currentElement, REF_ATTR));
                                if(appender != 0)
                                {
                                        LogLog::debug(LOG4CXX_STR("Adding appender named [")+ refName+
                                        LOG4CXX_STR("] to logger [")+logger->getName()+LOG4CXX_STR("]."));
                                }
                                else
                                {
                                        LogLog::debug(LOG4CXX_STR("Appender named [")+ refName +
                                                LOG4CXX_STR("] not found."));
                                }

                                logger->addAppender(appender);

                        }
                        else if(tagName == LEVEL_TAG)
                        {
                                parseLevel(currentElement, logger, isRoot);
                        }
                        else if(tagName == PRIORITY_TAG)
                        {
                                parseLevel(currentElement, logger, isRoot);
                        }
                        else if(tagName == PARAM_TAG)
                        {
                                setParameter(currentElement, propSetter);
                        }
    }
    Pool p;
    propSetter.activate(p);
}

/**
 Used internally to parse a layout element.
*/
LayoutPtr DOMConfigurator::parseLayout (apr_xml_elem* layout_element)
{
        LogString className(subst(getAttribute(layout_element, CLASS_ATTR)));
        LogLog::debug(LOG4CXX_STR("Parsing layout of class: \"")+className+LOG4CXX_STR("\""));
        try
        {
                ObjectPtr instance = Loader::loadClass(className).newInstance();
                LayoutPtr layout = instance;
                PropertySetter propSetter(layout);

                for(apr_xml_elem* currentElement = layout_element->first_child;
                    currentElement;
                    currentElement = currentElement->next) {
                                std::string tagName(currentElement->name);
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                }

                Pool p;
                propSetter.activate(p);
                return layout;
        }
        catch (Exception& oops)
        {
                LogLog::error(LOG4CXX_STR("Could not create the Layout. Reported error follows."),
                        oops);
                return 0;
        }
}

/**
 Used internally to parse a triggering policy
*/
TriggeringPolicyPtr DOMConfigurator::parseTriggeringPolicy (apr_xml_elem* layout_element)
{
        LogString className = subst(getAttribute(layout_element, CLASS_ATTR));
        LogLog::debug(LOG4CXX_STR("Parsing triggering policy of class: \"")+className+LOG4CXX_STR("\""));
        try
        {
                ObjectPtr instance = Loader::loadClass(className).newInstance();
                TriggeringPolicyPtr layout = instance;
                PropertySetter propSetter(layout);

                for (apr_xml_elem* currentElement = layout_element->first_child;
                     currentElement;
                     currentElement = currentElement->next) {
                                std::string tagName(currentElement->name);
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                                else if (tagName == FILTER_TAG) {
                                  std::vector<log4cxx::spi::FilterPtr> filters;
                                  parseFilters(currentElement, filters);
                                  FilterBasedTriggeringPolicyPtr fbtp(instance);
                                  if (fbtp != NULL) {
                                    for(std::vector<log4cxx::spi::FilterPtr>::iterator iter = filters.begin();
                                        iter != filters.end();
                                        iter++) {
                                        fbtp->addFilter(*iter);
                                    }
                                  }
                                }
                }

                Pool p;
                propSetter.activate(p);
                return layout;
        }
        catch (Exception& oops)
        {
                LogLog::error(LOG4CXX_STR("Could not create the TriggeringPolicy. Reported error follows."),
                        oops);
                return 0;
        }
}

/**
 Used internally to parse a triggering policy
*/
RollingPolicyPtr DOMConfigurator::parseRollingPolicy (apr_xml_elem* layout_element)
{
        LogString className = subst(getAttribute(layout_element, CLASS_ATTR));
        LogLog::debug(LOG4CXX_STR("Parsing rolling policy of class: \"")+className+LOG4CXX_STR("\""));
        try
        {
                ObjectPtr instance = Loader::loadClass(className).newInstance();
                RollingPolicyPtr layout = instance;
                PropertySetter propSetter(layout);

                for(apr_xml_elem* currentElement = layout_element->first_child;
                    currentElement;
                    currentElement = currentElement->next) {
                                std::string tagName(currentElement->name);
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                        }
                }

                Pool p;
                propSetter.activate(p);
                return layout;
        }
        catch (Exception& oops)
        {
                LogLog::error(LOG4CXX_STR("Could not create the RollingPolicy. Reported error follows."),
                        oops);
                return 0;
        }
}



/**
 Used internally to parse a level  element.
*/
void DOMConfigurator::parseLevel(apr_xml_elem* element, LoggerPtr logger, bool isRoot)
{
    LogString loggerName = logger->getName();
    if(isRoot)
        {
                loggerName = LOG4CXX_STR("root");
    }

    LogString levelStr(subst(getAttribute(element, VALUE_ATTR)));
        LogLog::debug(LOG4CXX_STR("Level value for ")+loggerName+LOG4CXX_STR(" is [")+levelStr+LOG4CXX_STR("]."));

    if (StringHelper::equalsIgnoreCase(levelStr,LOG4CXX_STR("INHERITED"), LOG4CXX_STR("inherited"))
        || StringHelper::equalsIgnoreCase(levelStr, LOG4CXX_STR("NULL"), LOG4CXX_STR("null")))
        {
                if(isRoot)
                {
                        LogLog::error(LOG4CXX_STR("Root level cannot be inherited. Ignoring directive."));
                }
                else
                {
                        logger->setLevel(0);
                }
    }
        else
        {
                LogString className(subst(getAttribute(element, CLASS_ATTR)));

                if (className.empty())
                {
                        logger->setLevel(OptionConverter::toLevel(levelStr, Level::getDebug()));
                }
                else
                {
                        LogLog::debug(LOG4CXX_STR("Desired Level sub-class: [") + className + LOG4CXX_STR("]"));

                        try
                        {
                                Level::LevelClass& levelClass =
                                        (Level::LevelClass&)Loader::loadClass(className);
                                LevelPtr level = levelClass.toLevel(levelStr);
                                logger->setLevel(level);
                        }
                        catch (Exception& oops)
                        {
                                LogLog::error(
                                        LOG4CXX_STR("Could not create level [") + levelStr +
                                        LOG4CXX_STR("]. Reported error follows."),
                                        oops);

                                return;
                        }
                        catch (...)
                        {
                                LogLog::error(
                                        LOG4CXX_STR("Could not create level [") + levelStr);

                                return;
                        }
                }
    }

        LogLog::debug(loggerName + LOG4CXX_STR(" level set to ") +
                logger->getEffectiveLevel()->toString());
}

void DOMConfigurator::setParameter(apr_xml_elem* elem, PropertySetter& propSetter)
{
        LogString name(subst(getAttribute(elem, NAME_ATTR)));
        LogString value(subst(getAttribute(elem, VALUE_ATTR)));
        Pool p;
        value = subst(value);
        propSetter.setProperty(name, value, p);
}

void DOMConfigurator::doConfigure(const File& filename, spi::LoggerRepositoryPtr& repository1)
{
       repository1->setConfigured(true);
        this->repository = repository1;
        LogString msg(LOG4CXX_STR("DOMConfigurator configuring file "));
        msg.append(filename.getName());
        msg.append(LOG4CXX_STR("..."));
        LogLog::debug(msg);

        loggerFactory = new DefaultLoggerFactory();

        Pool p;
        apr_file_t *fd;

        log4cxx_status_t rv = filename.open(&fd, APR_READ, APR_OS_DEFAULT, p);
        if (rv != APR_SUCCESS) {
            LogString msg2(LOG4CXX_STR("Could not open file ["));
            msg2.append(filename.getName());
            msg2.append(LOG4CXX_STR("]."));
            LogLog::error(msg2);
        } else {
            apr_xml_parser *parser;
            apr_xml_doc *doc;
            rv = apr_xml_parse_file((apr_pool_t*) p.getAPRPool(), &parser, &doc, fd, 2000);
            if (rv != APR_SUCCESS) {
                char errbuf[2000];
                char errbufXML[2000];
                LogString msg2(LOG4CXX_STR("Error parsing file ["));
                msg2.append(filename.getName());
                msg2.append(LOG4CXX_STR("], "));
                apr_strerror(rv, errbuf, sizeof(errbuf));
                LOG4CXX_DECODE_CHAR(lerrbuf, std::string(errbuf));
                apr_xml_parser_geterror(parser, errbufXML, sizeof(errbufXML));
                LOG4CXX_DECODE_CHAR(lerrbufXML, std::string(errbufXML));
                msg2.append(lerrbuf);
                msg2.append(lerrbufXML);
                LogLog::error(msg2);
            } else {
                AppenderMap appenders;
                parse(doc->root, doc, appenders);
            }
        }
}

void DOMConfigurator::configure(const std::string& filename)
{
    LOG4CXX_DECODE_CHAR(fn, filename);
    DOMConfigurator().doConfigure(fn, LogManager::getLoggerRepository());
}

#if LOG4CXX_HAS_WCHAR_T
void DOMConfigurator::configure(const std::wstring& filename)
{
    LOG4CXX_DECODE_WCHAR(fn, filename);
    DOMConfigurator().doConfigure(fn, LogManager::getLoggerRepository());
}
#endif

void DOMConfigurator::configureAndWatch(const std::string& filename)
{
  LOG4CXX_DECODE_CHAR(fn, filename);
  configureAndWatch(fn, FileWatchdog::DEFAULT_DELAY);
}

#if LOG4CXX_HAS_WCHAR_T
void DOMConfigurator::configureAndWatch(const std::wstring& filename)
{
  LOG4CXX_DECODE_WCHAR(fn, filename);
  configureAndWatch(fn, FileWatchdog::DEFAULT_DELAY);
}
#endif

void DOMConfigurator::configureAndWatch(const std::string& filename, long delay)
{
  LOG4CXX_DECODE_CHAR(fn, filename);
        XMLWatchdog * xdog = new XMLWatchdog(fn);
        xdog->setDelay(delay);
        xdog->start();
}
#if LOG4CXX_HAS_WCHAR_T
void DOMConfigurator::configureAndWatch(const std::wstring& filename, long delay)
{
  LOG4CXX_DECODE_WCHAR(fn, filename);
        XMLWatchdog * xdog = new XMLWatchdog(fn);
        xdog->setDelay(delay);
        xdog->start();
}
#endif

void DOMConfigurator::parse(apr_xml_elem* element,
                            apr_xml_doc* doc,
                            AppenderMap& appenders)
{
    std::string rootElementName(element->name);

    if (rootElementName != CONFIGURATION_TAG)
        {
                if(rootElementName == OLD_CONFIGURATION_TAG)
                {
                        //LogLog::warn(LOG4CXX_STR("The <")+String(OLD_CONFIGURATION_TAG)+
                        // LOG4CXX_STR("> element has been deprecated."));
                        //LogLog::warn(LOG4CXX_STR("Use the <")+String(CONFIGURATION_TAG)+
                        // LOG4CXX_STR("> element instead."));
                }
                else
                {
                        LogLog::error(LOG4CXX_STR("DOM element is - not a <configuration> element."));
                        return;
                }
    }

    LogString debugAttrib = subst(getAttribute(element, INTERNAL_DEBUG_ATTR));

    static const LogString NuLL(LOG4CXX_STR("NULL"));
    LogLog::debug(LOG4CXX_STR("debug attribute= \"") + debugAttrib +LOG4CXX_STR("\"."));
    // if the log4j.dtd is not specified in the XML file, then the
    // "debug" attribute is returned as the empty string.
    if(!debugAttrib.empty() && debugAttrib != NuLL)
        {
                LogLog::setInternalDebugging(OptionConverter::toBoolean(debugAttrib, true));
    }
        else
        {
                LogLog::debug(LOG4CXX_STR("Ignoring internalDebug attribute."));
    }


    LogString confDebug = subst(getAttribute(element, CONFIG_DEBUG_ATTR));
    if(!confDebug.empty() && confDebug != NuLL)
        {
                LogLog::warn(LOG4CXX_STR("The \"configDebug\" attribute is deprecated."));
                LogLog::warn(LOG4CXX_STR("Use the \"internalDebug\" attribute instead."));
                LogLog::setInternalDebugging(OptionConverter::toBoolean(confDebug, true));
    }

    LogString thresholdStr = subst(getAttribute(element, THRESHOLD_ATTR));
    LogLog::debug(LOG4CXX_STR("Threshold =\"") + thresholdStr +LOG4CXX_STR("\"."));
    if(!thresholdStr.empty() && thresholdStr != NuLL)
        {
                repository->setThreshold(thresholdStr);
    }

    apr_xml_elem* currentElement;
    for(currentElement = element->first_child;
        currentElement;
        currentElement = currentElement->next) {
                        std::string tagName(currentElement->name);

                        if (tagName == CATEGORY_FACTORY_TAG)
                        {
                                parseLoggerFactory(currentElement);
                        }
    }

    for(currentElement = element->first_child;
        currentElement;
        currentElement = currentElement->next) {
                        std::string tagName(currentElement->name);

                        if (tagName == CATEGORY || tagName == LOGGER)
                        {
                                parseLogger(currentElement, doc, appenders);
                        }
                        else if (tagName == ROOT_TAG)
                        {
                                parseRoot(currentElement, doc, appenders);
                        }
    }
}

LogString DOMConfigurator::subst(const LogString& value)
{
    try
        {
                return OptionConverter::substVars(value, props);
    }
        catch(IllegalArgumentException& e)
        {
                LogLog::warn(LOG4CXX_STR("Could not perform variable substitution."), e);
                return value;
    }
}


LogString DOMConfigurator::getAttribute(apr_xml_elem* element, 
                                        const std::string& attrName) {
    LogString attrValue;
    for(apr_xml_attr* attr = element->attr;
        attr;
        attr = attr->next) {
        if (attrName == attr->name) {
            ByteBuffer buf((char*) attr->value, strlen(attr->value));
            CharsetDecoder::getUTF8Decoder()->decode(buf, attrValue);
        }
    }
    return attrValue;
}
