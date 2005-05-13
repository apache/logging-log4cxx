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

#include <log4cxx/private/log4cxx_private.h>
#ifdef LOG4CXX_HAVE_XML

#if defined(_WIN32)
#include <windows.h>
#include <log4cxx/helpers/msxml.h>
#else
#include <log4cxx/helpers/gnomexml.h>
#endif


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
#include <log4cxx/defaultcategoryfactory.h>
#include <log4cxx/helpers/filewatchdog.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/pool.h>
#include <sstream>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::config;

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

AppenderPtr AppenderMap::get(const LogString& appenderName)
{
        AppenderPtr appender;
        std::map<LogString, AppenderPtr>::iterator it;
        it = map.find(appenderName);

        if (it != map.end())
        {
                appender = it->second;
        }

        return appender;
}

void AppenderMap::put(const LogString& appenderName, AppenderPtr appender)
{
        map.insert(std::map<LogString, AppenderPtr>::value_type(appenderName, appender));
}

IMPLEMENT_LOG4CXX_OBJECT(DOMConfigurator)

#define CONFIGURATION_TAG LOG4CXX_STR("log4j:configuration")
#define OLD_CONFIGURATION_TAG LOG4CXX_STR("configuration")
#define APPENDER_TAG LOG4CXX_STR("appender")
#define APPENDER_REF_TAG LOG4CXX_STR("appender-ref")
#define PARAM_TAG LOG4CXX_STR("param")
#define LAYOUT_TAG LOG4CXX_STR("layout")
#define CATEGORY LOG4CXX_STR("category")
#define LOGGER LOG4CXX_STR("logger")
#define LOGGER_REF LOG4CXX_STR("logger-ref")
#define CATEGORY_FACTORY_TAG LOG4CXX_STR("categoryFactory")
#define NAME_ATTR LOG4CXX_STR("name")
#define CLASS_ATTR LOG4CXX_STR("class")
#define VALUE_ATTR LOG4CXX_STR("value")
#define ROOT_TAG LOG4CXX_STR("root")
#define ROOT_REF LOG4CXX_STR("root-ref")
#define LEVEL_TAG LOG4CXX_STR("level")
#define PRIORITY_TAG LOG4CXX_STR("priority")
#define FILTER_TAG LOG4CXX_STR("filter")
#define ERROR_HANDLER_TAG LOG4CXX_STR("errorHandler")
#define REF_ATTR LOG4CXX_STR("ref")
#define ADDITIVITY_ATTR LOG4CXX_STR("additivity")
#define THRESHOLD_ATTR LOG4CXX_STR("threshold")
#define CONFIG_DEBUG_ATTR LOG4CXX_STR("configDebug")
#define INTERNAL_DEBUG_ATTR LOG4CXX_STR("debug")

DOMConfigurator::DOMConfigurator()
   : appenderBag(), props(), repository() {
}

/**
Used internally to parse appenders by IDREF name.
*/
AppenderPtr DOMConfigurator::findAppenderByName(XMLDOMDocumentPtr doc, const LogString& appenderName)
{
    AppenderPtr appender = ((AppenderMap *)appenderBag)->get(appenderName);

    if (appender != 0)
        {
                return appender;
    }
        else
        {
                XMLDOMElementPtr element = doc->getElementById(APPENDER_TAG, appenderName);

                if(element == 0)
                {
                        LogLog::error(LOG4CXX_STR("No appender named [")+
                                appenderName+LOG4CXX_STR("] could be found."));
                        return 0;
                }
                else
                {
                        appender = parseAppender(element);
                        ((AppenderMap *)appenderBag)->put(appenderName, appender);
                        return appender;
                }
    }
}

/**
 Used internally to parse appenders by IDREF element.
*/
AppenderPtr DOMConfigurator::findAppenderByReference(XMLDOMElementPtr appenderRef)
{
        LogString appenderName = subst(appenderRef->getAttribute(REF_ATTR));
        XMLDOMDocumentPtr doc = appenderRef->getOwnerDocument();
        return findAppenderByName(doc, appenderName);
}

/**
Used internally to parse an appender element.
*/
AppenderPtr DOMConfigurator::parseAppender(XMLDOMElementPtr appenderElement)
{
    LogString className = subst(appenderElement->getAttribute(CLASS_ATTR));
        LogLog::debug(LOG4CXX_STR("Class name: [") + className+LOG4CXX_STR("]"));
    try
        {
                ObjectPtr instance = Loader::loadClass(className).newInstance();
                AppenderPtr appender = instance;
                PropertySetter propSetter(appender);

                appender->setName(subst(appenderElement->getAttribute(NAME_ATTR)));

                XMLDOMNodeListPtr children = appenderElement->getChildNodes();
                int length = children->getLength();

                for (int loop = 0; loop < length; loop++)
                {
                        XMLDOMNodePtr currentNode = children->item(loop);

                        /* We're only interested in Elements */
                        if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                        {
                                XMLDOMElementPtr currentElement = currentNode;
                                LogString tagName = currentElement->getTagName();

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
                                        parseFilters(currentElement, appender);
                                }
                                else if (tagName == ERROR_HANDLER_TAG)
                                {
                                        parseErrorHandler(currentElement, appender);
                                }
                                else if (tagName == APPENDER_REF_TAG)
                                {
                                        LogString refName = subst(currentElement->getAttribute(REF_ATTR));
                                        if(appender->instanceof(AppenderAttachable::getStaticClass()))
                                        {
                                                AppenderAttachablePtr aa = appender;
                                                LogLog::debug(LOG4CXX_STR("Attaching appender named [")+
                                                        refName+LOG4CXX_STR("] to appender named [")+
                                                        appender->getName()+LOG4CXX_STR("]."));
                                                aa->addAppender(findAppenderByReference(currentElement));
                                        }
                                        else
                                        {
                                                LogLog::error(LOG4CXX_STR("Requesting attachment of appender named [")+
                                                        refName+ LOG4CXX_STR("] to appender named [")+ appender->getName()+
                                                        LOG4CXX_STR("] which does not implement AppenderAttachable."));
                                        }
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
void DOMConfigurator::parseErrorHandler(XMLDOMElementPtr element, AppenderPtr appender)
{
    ErrorHandlerPtr eh = OptionConverter::instantiateByClassName(
                subst(element->getAttribute(CLASS_ATTR)),
                ErrorHandler::getStaticClass(),
                0);

    if(eh != 0)
        {
                eh->setAppender(appender);

                PropertySetter propSetter(eh);
                XMLDOMNodeListPtr children = element->getChildNodes();
                int length = children->getLength();

                for (int loop = 0; loop < length; loop++)
                {
                        XMLDOMNodePtr currentNode = children->item(loop);
                        if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                        {
                                XMLDOMElementPtr currentElement = currentNode;
                                LogString tagName = currentElement->getTagName();
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                                else if(tagName == APPENDER_REF_TAG)
                                {
                                        eh->setBackupAppender(findAppenderByReference(currentElement));
                                }
                                else if(tagName == LOGGER_REF)
                                {
                                        LogString loggerName = currentElement->getAttribute(REF_ATTR);
                                        LoggerPtr logger = repository->getLogger(loggerName, loggerFactory);
                                        eh->setLogger(logger);
                                }
                                else if(tagName == ROOT_REF)
                                {
                                        LoggerPtr root = repository->getRootLogger();
                                        eh->setLogger(root);
                                }
                        }
                }
        Pool p;
                propSetter.activate(p);
                appender->setErrorHandler(eh);
    }
}

/**
 Used internally to parse a filter element.
*/
void DOMConfigurator::parseFilters(XMLDOMElementPtr element, AppenderPtr appender)
{
        LogString clazz = subst(element->getAttribute(CLASS_ATTR));
        FilterPtr filter = OptionConverter::instantiateByClassName(clazz,
                Filter::getStaticClass(), 0);

        if(filter != 0)
        {
                PropertySetter propSetter(filter);
                XMLDOMNodeListPtr children = element->getChildNodes();
                int length = children->getLength();

                for (int loop = 0; loop < length; loop++)
                {
                        XMLDOMNodePtr currentNode = children->item(loop);
                        if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                        {
                                XMLDOMElementPtr currentElement = currentNode;
                                LogString tagName = currentElement->getTagName();
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                        }
                }
        Pool p;
                propSetter.activate(p);
                LogLog::debug(LOG4CXX_STR("Adding filter of type [")+filter->getClass().toString()
                        +LOG4CXX_STR("] to appender named [")+appender->getName()+LOG4CXX_STR("]."));
                appender->addFilter(filter);
        }
}

/**
Used internally to parse an category element.
*/
void DOMConfigurator::parseLogger(XMLDOMElementPtr loggerElement)
{
        // Create a new org.apache.log4j.Category object from the <category> element.
        LogString loggerName = subst(loggerElement->getAttribute(NAME_ATTR));

        LogLog::debug(LOG4CXX_STR("Retreiving an instance of Logger."));
        LoggerPtr logger = repository->getLogger(loggerName, loggerFactory);

        // Setting up a category needs to be an atomic operation, in order
        // to protect potential log operations while category
        // configuration is in progress.
        synchronized sync(logger->getMutex());
        bool additivity = OptionConverter::toBoolean(
                subst(loggerElement->getAttribute(ADDITIVITY_ATTR)),
                true);

        LogLog::debug(LOG4CXX_STR("Setting [")+logger->getName()+LOG4CXX_STR("] additivity to [")+
                (additivity ? LogString(LOG4CXX_STR("true")) : LogString(LOG4CXX_STR("false")))+LOG4CXX_STR("]."));
        logger->setAdditivity(additivity);
        parseChildrenOfLoggerElement(loggerElement, logger, false);
}

/**
 Used internally to parse the logger factory element.
*/
void DOMConfigurator::parseLoggerFactory(XMLDOMElementPtr factoryElement)
{
        LogString className = subst(factoryElement->getAttribute(CLASS_ATTR));

        if(className.empty())
        {
                LogLog::error(LOG4CXX_STR("Logger Factory tag ") + LogString(CLASS_ATTR) +
                        LOG4CXX_STR(" attribute not found."));
                LogLog::debug(LOG4CXX_STR("No Category Logger configured."));
        }
        else
        {
                LogLog::debug(LOG4CXX_STR("Desired logger factory: [")+className+LOG4CXX_STR("]"));
                loggerFactory = OptionConverter::instantiateByClassName(
                        className,
                        LoggerFactory::getStaticClass(),
                        0);
                PropertySetter propSetter(loggerFactory);

                XMLDOMElementPtr currentElement = 0;
                XMLDOMNodePtr currentNode = 0;
                XMLDOMNodeListPtr children = factoryElement->getChildNodes();
                int length = children->getLength();

                for (int loop=0; loop < length; loop++)
                {
                        currentNode = children->item(loop);
                        if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                        {
                                currentElement = currentNode;
                                if (currentElement->getTagName() == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
                        }
                }
        }
}

/**
 Used internally to parse the roor category element.
*/
void DOMConfigurator::parseRoot(XMLDOMElementPtr rootElement)
{
        LoggerPtr root = repository->getRootLogger();
        // category configuration needs to be atomic
        synchronized sync(root->getMutex());
        parseChildrenOfLoggerElement(rootElement, root, true);
}

/**
 Used internally to parse the children of a logger element.
*/
void DOMConfigurator::parseChildrenOfLoggerElement(
        XMLDOMElementPtr loggerElement, LoggerPtr logger, bool isRoot)
{

    PropertySetter propSetter(logger);

    // Remove all existing appenders from logger. They will be
    // reconstructed if need be.
    logger->removeAllAppenders();


    XMLDOMNodeListPtr children = loggerElement->getChildNodes();
    int length = children->getLength();

    for (int loop = 0; loop < length; loop++)
        {
                XMLDOMNodePtr currentNode = children->item(loop);

                if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                {
                        XMLDOMElementPtr currentElement = currentNode;
                        LogString tagName = currentElement->getTagName();

                        if (tagName == APPENDER_REF_TAG)
                        {
                                AppenderPtr appender = findAppenderByReference(currentElement);
                                LogString refName =  subst(currentElement->getAttribute(REF_ATTR));
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
    }
    Pool p;
    propSetter.activate(p);
}

/**
 Used internally to parse a layout element.
*/
LayoutPtr DOMConfigurator::parseLayout (XMLDOMElementPtr layout_element)
{
        LogString className = subst(layout_element->getAttribute(CLASS_ATTR));
        LogLog::debug(LOG4CXX_STR("Parsing layout of class: \"")+className+LOG4CXX_STR("\""));
        try
        {
                ObjectPtr instance = Loader::loadClass(className).newInstance();
                LayoutPtr layout = instance;
                PropertySetter propSetter(layout);

                XMLDOMNodeListPtr params  = layout_element->getChildNodes();
                int length    = params->getLength();

                for (int loop = 0; loop < length; loop++)
                {
                        XMLDOMNodePtr currentNode = params->item(loop);
                        if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                        {
                                XMLDOMElementPtr currentElement = currentNode;
                                LogString tagName = currentElement->getTagName();
                                if(tagName == PARAM_TAG)
                                {
                                        setParameter(currentElement, propSetter);
                                }
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
 Used internally to parse a level  element.
*/
void DOMConfigurator::parseLevel(XMLDOMElementPtr element, LoggerPtr logger, bool isRoot)
{
    LogString loggerName = logger->getName();
    if(isRoot)
        {
                loggerName = LOG4CXX_STR("root");
    }

    LogString levelStr = subst(element->getAttribute(VALUE_ATTR));
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
                LogString className = subst(element->getAttribute(CLASS_ATTR));

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

void DOMConfigurator::setParameter(XMLDOMElementPtr elem, PropertySetter& propSetter)
{
        LogString name = subst(elem->getAttribute(NAME_ATTR));
        LogString value = elem->getAttribute(VALUE_ATTR);
        Pool p;
        value = subst(value);
        propSetter.setProperty(name, value, p);
}

void DOMConfigurator::doConfigure(const File& filename, spi::LoggerRepositoryPtr& repository)
{
       repository->setConfigured(true);
        this->repository = repository;
        std::basic_ostringstream<logchar> os(LOG4CXX_STR("DOMConfigurator configuring file "));
        os << filename.getName() << LOG4CXX_STR("...");
        LogLog::debug(os.str());

        appenderBag = new AppenderMap();
        loggerFactory = new DefaultCategoryFactory();

        try
        {
#ifdef _WIN32
                XMLDOMDocumentPtr doc = new MsXMLDOMDocument();
#else
                XMLDOMDocumentPtr doc = new GnomeXMLDOMDocument();
#endif
                doc->load(filename);
                parse(doc->getDocumentElement());
    }
        catch (Exception& e)
        {
                // I know this is miserable..
        std::basic_ostringstream<logchar> os(LOG4CXX_STR("Could not parse input source ["));
        os << filename.getName() << LOG4CXX_STR("].");
                LogLog::error(os.str(), e);
    }

        delete (AppenderMap *)appenderBag;
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

/**
 Used internally to configure the log4j framework by parsing a DOM
 tree of XML elements based on <a
 href="doc-files/log4j.dtd">log4j.dtd</a>.

*/
void DOMConfigurator::parse(XMLDOMElementPtr element)
{
    LogString rootElementName = element->getTagName();

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
                        LogLog::error(LOG4CXX_STR("DOM element is - not a <")+
                                LogString(CONFIGURATION_TAG)+LOG4CXX_STR("> element."));
                        return;
                }
    }

    LogString debugAttrib = subst(element->getAttribute(INTERNAL_DEBUG_ATTR));

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
                LogLog::debug(LOG4CXX_STR("Ignoring ") + LogString(INTERNAL_DEBUG_ATTR)
                        + LOG4CXX_STR(" attribute."));
    }


    LogString confDebug = subst(element->getAttribute(CONFIG_DEBUG_ATTR));
    if(!confDebug.empty() && confDebug != NuLL)
        {
                LogLog::warn(LOG4CXX_STR("The \"")+LogString(CONFIG_DEBUG_ATTR)+
                        LOG4CXX_STR("\" attribute is deprecated."));
                LogLog::warn(LOG4CXX_STR("Use the \"")+LogString(INTERNAL_DEBUG_ATTR)+
                        LOG4CXX_STR("\" attribute instead."));
                LogLog::setInternalDebugging(OptionConverter::toBoolean(confDebug, true));
    }

    LogString thresholdStr = subst(element->getAttribute(THRESHOLD_ATTR));
    LogLog::debug(LOG4CXX_STR("Threshold =\"") + thresholdStr +LOG4CXX_STR("\"."));
    if(!thresholdStr.empty() && thresholdStr != NuLL)
        {
                repository->setThreshold(thresholdStr);
    }

    LogString tagName;
    XMLDOMElementPtr currentElement;
    XMLDOMNodePtr currentNode;
    XMLDOMNodeListPtr children = element->getChildNodes();
    int length = children->getLength();
        int loop;

    for (loop = 0; loop < length; loop++)
        {
                currentNode = children->item(loop);
                if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                {
                        currentElement = currentNode;
                        tagName = currentElement->getTagName();

                        if (tagName == CATEGORY_FACTORY_TAG)
                        {
                                parseLoggerFactory(currentElement);
                        }
                }
    }

    for (loop = 0; loop < length; loop++)
        {
                currentNode = children->item(loop);
                if (currentNode->getNodeType() == XMLDOMNode::ELEMENT_NODE)
                {
                        currentElement =  currentNode;
                        tagName = currentElement->getTagName();

                        if (tagName == CATEGORY || tagName == LOGGER)
                        {
                                parseLogger(currentElement);
                        }
                        else if (tagName == ROOT_TAG)
                        {
                                parseRoot(currentElement);
                        }
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

#endif // LOG4CXX_HAVE_XML
