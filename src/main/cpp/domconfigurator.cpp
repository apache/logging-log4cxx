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
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/appender.h>
#include <log4cxx/asyncappender.h>
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
#if LOG4CXX_ABI_VERSION <= 15
#include <log4cxx/defaultloggerfactory.h>
#else
#include <log4cxx/spi/loggerfactory.h>
#endif
#include <log4cxx/helpers/filewatchdog.h>
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
#include <log4cxx/net/smtpappender.h>
#include <log4cxx/helpers/messagebuffer.h>
#include <log4cxx/helpers/threadutility.h>
#include <log4cxx/helpers/singletonholder.h>

#define LOG4CXX 1
#include <log4cxx/helpers/aprinitializer.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::xml;
using namespace LOG4CXX_NS::helpers;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::config;
using namespace LOG4CXX_NS::rolling;

#define MAX_ATTRIBUTE_NAME_LEN 2000

struct DOMConfigurator::DOMConfiguratorPrivate
{
	helpers::Properties props = Configurator::properties();
	spi::LoggerRepositoryPtr repository;
	spi::LoggerFactoryPtr loggerFactory;
	bool appenderAdded{ false };
};

namespace LOG4CXX_NS
{
namespace xml
{
class XMLWatchdog  : public FileWatchdog
{
	public:
		XMLWatchdog(const File& filename) : FileWatchdog(filename)
		{
		}

		/**
		Call DOMConfigurator#doConfigure with the
		<code>filename</code> to reconfigure log4cxx.
		*/
		void doOnChange()
		{
			DOMConfigurator().doConfigure(file(),
				LogManager::getLoggerRepository());
		}

		static void startWatching(const File& filename, long delay)
		{
			using WatchdogHolder = SingletonHolder<XMLWatchdog>;
			auto pHolder = APRInitializer::getOrAddUnique<WatchdogHolder>
				( [&filename]() -> ObjectPtr
					{ return std::make_shared<WatchdogHolder>(filename); }
				);
			auto& xdog = pHolder->value();
			xdog.setFile(filename);
			xdog.setDelay(0 < delay ? delay : FileWatchdog::DEFAULT_DELAY);
			xdog.start();
		}
};
}
}

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
#define ASYNCHRONOUS_ATTR "asynchronous-logging"
#define THRESHOLD_ATTR "threshold"
#define STRINGSTREAM_ATTR "stringstream"
#define CONFIG_DEBUG_ATTR "configDebug"
#define INTERNAL_DEBUG_ATTR "debug"
#define INTERNAL_COLOR_ATTR "color"
#define THREAD_CONFIG_ATTR "threadConfiguration"

DOMConfigurator::DOMConfigurator()
	: m_priv(std::make_unique<DOMConfiguratorPrivate>())
{
}

DOMConfigurator::~DOMConfigurator() {}

/**
Used internally to parse appenders by IDREF name.
*/
AppenderPtr DOMConfigurator::findAppenderByName(LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* element,
	apr_xml_doc* doc,
	const LogString& appenderName,
	AppenderMap& appenders)
{
	AppenderPtr appender;
	std::string tagName(element->name);

	if (tagName == APPENDER_TAG)
	{
		if (appenderName == getAttribute(utf8Decoder, element, NAME_ATTR))
		{
			appender = parseAppender(p, utf8Decoder, element, doc, appenders);
		}
	}

	if (element->first_child && !appender)
	{
		appender = findAppenderByName(p, utf8Decoder, element->first_child, doc, appenderName, appenders);
	}

	if (element->next && !appender)
	{
		appender = findAppenderByName(p, utf8Decoder, element->next, doc, appenderName, appenders);
	}

	return appender;
}

/**
 Used internally to parse appenders by IDREF element.
*/
AppenderPtr DOMConfigurator::findAppenderByReference(
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* appenderRef,
	apr_xml_doc* doc,
	AppenderMap& appenders)
{
	AppenderPtr appender;
	LogString appenderName(subst(getAttribute(utf8Decoder, appenderRef, REF_ATTR)));
	if (appenderName.empty())
	{
		LogString msg(LOG4CXX_STR("["));
		utf8Decoder->decode(appenderRef->name, MAX_ATTRIBUTE_NAME_LEN, msg);
		msg += LOG4CXX_STR("] attribute [");
		utf8Decoder->decode(REF_ATTR, MAX_ATTRIBUTE_NAME_LEN, msg);
		msg += LOG4CXX_STR("] not found");
		LogLog::warn(msg);
		return appender;
	}
	AppenderMap::const_iterator match = appenders.find(appenderName);

	if (match != appenders.end())
	{
		appender = match->second;
	}
	else if (doc)
	{
		appender = findAppenderByName(p, utf8Decoder, doc->root, doc, appenderName, appenders);

		if (appender)
		{
			appenders.insert(AppenderMap::value_type(appenderName, appender));
		}
	}

	if (!appender)
	{
		LogLog::error(LOG4CXX_STR("No ") + Appender::getStaticClass().getName()
			+ LOG4CXX_STR(" named [") + appenderName + LOG4CXX_STR("] could be found."));
	}

	return appender;
}

/**
Used internally to parse an appender element.
*/
AppenderPtr DOMConfigurator::parseAppender(Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* appenderElement,
	apr_xml_doc* doc,
	AppenderMap& appenders)
{

	LogString className(subst(getAttribute(utf8Decoder, appenderElement, CLASS_ATTR)));
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("Desired ") + Appender::getStaticClass().getName()
					+ LOG4CXX_STR(" sub-class: [") + className + LOG4CXX_STR("]"));
	}

	try
	{
		ObjectPtr instance = ObjectPtr(Loader::loadClass(className).newInstance());
		AppenderPtr appender = LOG4CXX_NS::cast<Appender>(instance);
		if(!appender){
			LogLog::error(LOG4CXX_STR("Could not cast [") + className + LOG4CXX_STR("] to ") + Appender::getStaticClass().getName());
			return AppenderPtr();
		}
		PropertySetter propSetter(appender);

		appender->setName(subst(getAttribute(utf8Decoder, appenderElement, NAME_ATTR)));

		for (apr_xml_elem* currentElement = appenderElement->first_child;
			currentElement;
			currentElement = currentElement->next)
		{

			std::string tagName(currentElement->name);

			// Parse appender parameters
			if (tagName == PARAM_TAG)
			{
				setParameter(p, utf8Decoder, currentElement, propSetter);
			}
			// Set appender layout
			else if (tagName == LAYOUT_TAG)
			{
				appender->setLayout(parseLayout(p, utf8Decoder, currentElement));
			}
			// Add filters
			else if (tagName == FILTER_TAG)
			{
				std::vector<LOG4CXX_NS::spi::FilterPtr> filters;
				parseFilters(p, utf8Decoder, currentElement, filters);

				for (auto& item : filters)
				{
					appender->addFilter(item);
				}
			}
			else if (tagName == ERROR_HANDLER_TAG)
			{
				parseErrorHandler(p, utf8Decoder, currentElement, appender, doc, appenders);
			}
			else if (tagName == ROLLING_POLICY_TAG)
			{
				RollingPolicyPtr rollPolicy(parseRollingPolicy(p, utf8Decoder, currentElement));
				RollingFileAppenderPtr rfa = LOG4CXX_NS::cast<RollingFileAppender>(appender);

				if (rfa != NULL)
				{
					rfa->setRollingPolicy(rollPolicy);
				}
			}
			else if (tagName == TRIGGERING_POLICY_TAG)
			{
				ObjectPtr policy(parseTriggeringPolicy(p, utf8Decoder, currentElement));
				RollingFileAppenderPtr rfa = LOG4CXX_NS::cast<RollingFileAppender>(appender);
				TriggeringPolicyPtr policyPtr = LOG4CXX_NS::cast<TriggeringPolicy>(policy);

				if (rfa != NULL)
				{
					rfa->setTriggeringPolicy(policyPtr);
				}
				else
				{
					auto smtpa = LOG4CXX_NS::cast<LOG4CXX_NS::net::SMTPAppender>(appender);

					if (smtpa != NULL)
					{
						auto evaluator = LOG4CXX_NS::cast<TriggeringEventEvaluator>(policy);
						smtpa->setEvaluator(evaluator);
					}
				}
			}
			else if (tagName == APPENDER_REF_TAG)
			{
				if (appender->instanceof(AppenderAttachable::getStaticClass()))
				{
					AppenderAttachablePtr aa = LOG4CXX_NS::cast<AppenderAttachable>(appender);
					if (auto delegateAppender = findAppenderByReference(p, utf8Decoder, currentElement, doc, appenders))
					{
						if (LogLog::isDebugEnabled())
						{
							LogLog::debug(LOG4CXX_STR("Attaching ") + Appender::getStaticClass().getName()
								+ LOG4CXX_STR(" named [") + delegateAppender->getName() + LOG4CXX_STR("] to ") + Appender::getStaticClass().getName()
								+ LOG4CXX_STR(" named [") + appender->getName() + LOG4CXX_STR("]"));
						}
						aa->addAppender(delegateAppender);
					}
				}
				else
				{
					LogLog::error(LOG4CXX_STR("Cannot attach to ") + Appender::getStaticClass().getName()
						+ LOG4CXX_STR(" named [") + appender->getName() + LOG4CXX_STR("]")
						+ LOG4CXX_STR(" which does not implement ") + AppenderAttachable::getStaticClass().getName());
				}
			}
		}

		propSetter.activate(p);
		return appender;
	}
	/* Yes, it's ugly.  But all of these exceptions point to the same
	    problem: we can't create an Appender */
	catch (Exception& oops)
	{
		LogLog::error(LOG4CXX_STR("Could not create ") + Appender::getStaticClass().getName() + LOG4CXX_STR(" sub-class"), oops);
		return 0;
	}
}

/**
Used internally to parse an {@link ErrorHandler} element.
*/
void DOMConfigurator::parseErrorHandler(Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* element,
	AppenderPtr& appender,
	apr_xml_doc* doc,
	AppenderMap& appenders)
{

	ErrorHandlerPtr eh;
	std::shared_ptr<Object> obj = OptionConverter::instantiateByClassName(
			subst(getAttribute(utf8Decoder, element, CLASS_ATTR)),
			ErrorHandler::getStaticClass(),
			0);
	eh = LOG4CXX_NS::cast<ErrorHandler>(obj);

	if (eh != 0)
	{
		eh->setAppender(appender);

		PropertySetter propSetter(eh);

		for (apr_xml_elem* currentElement = element->first_child;
			currentElement;
			currentElement = currentElement->next)
		{
			std::string tagName(currentElement->name);

			if (tagName == PARAM_TAG)
			{
				setParameter(p, utf8Decoder, currentElement, propSetter);
			}
			else if (tagName == APPENDER_REF_TAG)
			{
				if (auto appender = findAppenderByReference(p, utf8Decoder, currentElement, doc, appenders))
					eh->setBackupAppender(appender);
			}
			else if (tagName == LOGGER_REF)
			{
				LogString loggerName(getAttribute(utf8Decoder, currentElement, REF_ATTR));
				LoggerPtr logger = m_priv->repository->getLogger(loggerName, m_priv->loggerFactory);
				eh->setLogger(logger);
			}
			else if (tagName == ROOT_REF)
			{
				LoggerPtr root = m_priv->repository->getRootLogger();
				eh->setLogger(root);
			}
		}

		propSetter.activate(p);
		std::shared_ptr<AppenderSkeleton> appSkeleton = LOG4CXX_NS::cast<AppenderSkeleton>(appender);

		if (appSkeleton != 0)
		{
			appSkeleton->setErrorHandler(eh);
		}
	}
}

/**
 Used internally to parse a filter element.
*/
void DOMConfigurator::parseFilters(Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* element,
	std::vector<LOG4CXX_NS::spi::FilterPtr>& filters)
{
	LogString clazz = subst(getAttribute(utf8Decoder, element, CLASS_ATTR));
	FilterPtr filter;
	std::shared_ptr<Object> obj = OptionConverter::instantiateByClassName(clazz,
			Filter::getStaticClass(), 0);
	filter = LOG4CXX_NS::cast<Filter>(obj);

	if (filter != 0)
	{
		PropertySetter propSetter(filter);

		for (apr_xml_elem* currentElement = element->first_child;
			currentElement;
			currentElement = currentElement->next)
		{
			std::string tagName(currentElement->name);

			if (tagName == PARAM_TAG)
			{
				setParameter(p, utf8Decoder, currentElement, propSetter);
			}
		}

		propSetter.activate(p);
		filters.push_back(filter);
	}
}

/**
Used internally to parse an category or logger element.
*/
void DOMConfigurator::parseLogger(
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* loggerElement,
	apr_xml_doc* doc,
	AppenderMap& appenders)
{
	// Create a new Logger object from the <category> element.
	LogString loggerName = subst(getAttribute(utf8Decoder, loggerElement, NAME_ATTR));

	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("Getting [") + loggerName + LOG4CXX_STR("]"));
	}
	LoggerPtr logger = m_priv->repository->getLogger(loggerName, m_priv->loggerFactory);

	// Setting up a logger needs to be an atomic operation, in order
	// to protect potential log operations while logger
	// configuration is in progress.
	bool additivity = OptionConverter::toBoolean(
			subst(getAttribute(utf8Decoder, loggerElement, ADDITIVITY_ATTR)),
			true);

	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("Setting [") + logger->getName() + LOG4CXX_STR("] additivity to [") +
			(additivity ? LogString(LOG4CXX_STR("true")) : LogString(LOG4CXX_STR("false"))) + LOG4CXX_STR("]"));
	}
	logger->setAdditivity(additivity);
	parseChildrenOfLoggerElement(p, utf8Decoder, loggerElement, logger, false, doc, appenders);
}

/**
 Used internally to parse the logger factory element.
*/
void DOMConfigurator::parseLoggerFactory(
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* factoryElement)
{
	LogString className(subst(getAttribute(utf8Decoder, factoryElement, CLASS_ATTR)));

	if (className.empty())
	{
		LogString msg(LOG4CXX_STR("["));
		utf8Decoder->decode(factoryElement->name, MAX_ATTRIBUTE_NAME_LEN, msg);
		msg += LOG4CXX_STR("] attribute [");
		utf8Decoder->decode(CLASS_ATTR, MAX_ATTRIBUTE_NAME_LEN, msg);
		msg += LOG4CXX_STR("] not found");
		LogLog::warn(msg);
	}
	else
	{
		auto obj = OptionConverter::instantiateByClassName
			( StringHelper::trim(className)
			, LoggerFactory::getStaticClass()
#if LOG4CXX_ABI_VERSION <= 15
			, std::make_shared<DefaultLoggerFactory>()
#else
			, std::make_shared<LoggerFactory>()
#endif
			);
		m_priv->loggerFactory = LOG4CXX_NS::cast<LoggerFactory>(obj);
		PropertySetter propSetter(m_priv->loggerFactory);

		for (apr_xml_elem* currentElement = factoryElement->first_child;
			currentElement;
			currentElement = currentElement->next)
		{
			std::string tagName(currentElement->name);

			if (tagName == PARAM_TAG)
			{
				setParameter(p, utf8Decoder, currentElement, propSetter);
			}
		}
	}
}

/**
 Used internally to parse the root logger element.
*/
void DOMConfigurator::parseRoot(
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* rootElement,
	apr_xml_doc* doc,
	AppenderMap& appenders)
{
	LoggerPtr root = m_priv->repository->getRootLogger();
	parseChildrenOfLoggerElement(p, utf8Decoder, rootElement, root, true, doc, appenders);
}

/**
 Used internally to parse the children of a logger element.
*/
void DOMConfigurator::parseChildrenOfLoggerElement(
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* loggerElement, LoggerPtr logger, bool isRoot,
	apr_xml_doc* doc,
	AppenderMap& appenders)
{
	PropertySetter propSetter(logger);
	std::vector<AppenderPtr> newappenders;
	AsyncAppenderPtr async;
	std::string sAsyncAttr{ ASYNCHRONOUS_ATTR };
	LOG4CXX_DECODE_CHAR(lsAsyncAttr, sAsyncAttr);
	auto pAppender = appenders.find(lsAsyncAttr);
	if (appenders.end() != pAppender)
		async = log4cxx::cast<AsyncAppender>(pAppender->second);

	for (apr_xml_elem* currentElement = loggerElement->first_child;
		currentElement;
		currentElement = currentElement->next)
	{
		std::string tagName(currentElement->name);

		if (tagName == APPENDER_REF_TAG)
		{
			if (auto appender = findAppenderByReference(p, utf8Decoder, currentElement, doc, appenders))
			{
				if (log4cxx::cast<AsyncAppender>(appender)) // An explicitly configured AsyncAppender?
					async.reset(); // Not required
				if (LogLog::isDebugEnabled())
				{
					LogLog::debug(LOG4CXX_STR("Adding ") + Appender::getStaticClass().getName()
						+ LOG4CXX_STR(" named [") + appender->getName() + LOG4CXX_STR("]")
						+ LOG4CXX_STR(" to logger [") + logger->getName() + LOG4CXX_STR("]"));
				}
				newappenders.push_back(appender);
				if (async)
					async->addAppender(appender);
			}
		}
		else if (tagName == LEVEL_TAG)
		{
			parseLevel(p, utf8Decoder, currentElement, logger, isRoot);
		}
		else if (tagName == PRIORITY_TAG)
		{
			parseLevel(p, utf8Decoder, currentElement, logger, isRoot);
		}
		else if (tagName == PARAM_TAG)
		{
			setParameter(p, utf8Decoder, currentElement, propSetter);
		}
	}
	if (async)
	{
		logger->replaceAppenders({async});
		m_priv->appenderAdded = true;
	}
	else if (newappenders.empty())
		logger->removeAllAppenders();
	else
	{
		logger->replaceAppenders(newappenders);
		m_priv->appenderAdded = true;
	}
	propSetter.activate(p);
}

/**
 Used internally to parse a layout element.
*/
LayoutPtr DOMConfigurator::parseLayout (
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* layout_element)
{
	LogString className(subst(getAttribute(utf8Decoder, layout_element, CLASS_ATTR)));
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("Desired ") + Layout::getStaticClass().getName()
					+ LOG4CXX_STR(" sub-class: [") + className + LOG4CXX_STR("]"));
	}

	try
	{
		ObjectPtr instance = ObjectPtr(Loader::loadClass(className).newInstance());
		LayoutPtr layout = LOG4CXX_NS::cast<Layout>(instance);
		PropertySetter propSetter(layout);

		for (apr_xml_elem* currentElement = layout_element->first_child;
			currentElement;
			currentElement = currentElement->next)
		{
			std::string tagName(currentElement->name);

			if (tagName == PARAM_TAG)
			{
				setParameter(p, utf8Decoder, currentElement, propSetter);
			}
		}

		propSetter.activate(p);
		return layout;
	}
	catch (Exception& oops)
	{
		LogLog::error(LOG4CXX_STR("Could not create ") + Layout::getStaticClass().getName() + LOG4CXX_STR(" sub-class"), oops);
		return 0;
	}
}

/**
 Used internally to parse a triggering policy
*/
ObjectPtr DOMConfigurator::parseTriggeringPolicy (
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* policy_element)
{
	LogString className = subst(getAttribute(utf8Decoder, policy_element, CLASS_ATTR));
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("Desired ") + TriggeringPolicy::getStaticClass().getName()
					+ LOG4CXX_STR(" sub-class: [") + className + LOG4CXX_STR("]"));
	}

	try
	{
		ObjectPtr instance = ObjectPtr(Loader::loadClass(className).newInstance());
		PropertySetter propSetter(instance);

		for (apr_xml_elem* currentElement = policy_element->first_child;
			currentElement;
			currentElement = currentElement->next)
		{
			std::string tagName(currentElement->name);

			if (tagName == PARAM_TAG)
			{
				setParameter(p, utf8Decoder, currentElement, propSetter);
			}
			else if (tagName == FILTER_TAG)
			{
				std::vector<LOG4CXX_NS::spi::FilterPtr> filters;
				parseFilters(p, utf8Decoder, currentElement, filters);
				FilterBasedTriggeringPolicyPtr fbtp = LOG4CXX_NS::cast<FilterBasedTriggeringPolicy>(instance);

				if (fbtp != NULL)
				{
					for (auto& item : filters)
					{
						fbtp->addFilter(item);
					}
				}
			}
		}

		propSetter.activate(p);
		return instance;
	}
	catch (Exception& oops)
	{
		LogLog::error(LOG4CXX_STR("Could not create ") + TriggeringPolicy::getStaticClass().getName() + LOG4CXX_STR(" sub-class"), oops);
		return 0;
	}
}

/**
 Used internally to parse a triggering policy
*/
RollingPolicyPtr DOMConfigurator::parseRollingPolicy (
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* policy_element)
{
	LogString className = subst(getAttribute(utf8Decoder, policy_element, CLASS_ATTR));
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("Desired ") + RollingPolicy::getStaticClass().getName()
					+ LOG4CXX_STR(" sub-class: [") + className + LOG4CXX_STR("]"));
	}

	try
	{
		ObjectPtr instance = ObjectPtr(Loader::loadClass(className).newInstance());
		PropertySetter propSetter(instance);

		for (apr_xml_elem* currentElement = policy_element->first_child;
			currentElement;
			currentElement = currentElement->next)
		{
			std::string tagName(currentElement->name);

			if (tagName == PARAM_TAG)
			{
				setParameter(p, utf8Decoder, currentElement, propSetter);
			}
		}

		propSetter.activate(p);
		return LOG4CXX_NS::cast<RollingPolicy>(instance);
	}
	catch (Exception& oops)
	{
		LogLog::error(LOG4CXX_STR("Could not create ") + RollingPolicy::getStaticClass().getName() + LOG4CXX_STR(" sub-class"), oops);
		return 0;
	}
}



/**
 Used internally to parse a level  element.
*/
void DOMConfigurator::parseLevel(
	LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* element, LoggerPtr logger, bool isRoot)
{
	LogString loggerName = logger->getName();

	if (isRoot)
	{
		loggerName = LOG4CXX_STR("root");
	}

	LogString levelStr(subst(getAttribute(utf8Decoder, element, VALUE_ATTR)));
	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("Setting [") + loggerName + LOG4CXX_STR("] level to [") + levelStr + LOG4CXX_STR("]"));
	}

	if (StringHelper::equalsIgnoreCase(levelStr, LOG4CXX_STR("INHERITED"), LOG4CXX_STR("inherited"))
		|| StringHelper::equalsIgnoreCase(levelStr, LOG4CXX_STR("NULL"), LOG4CXX_STR("null")))
	{
		if (isRoot)
		{
			LogLog::error(LOG4CXX_STR("Root level cannot be ") + levelStr + LOG4CXX_STR(". Ignoring directive."));
		}
		else
		{
			logger->setLevel(0);
		}
	}
	else
	{
		LogString className(subst(getAttribute(utf8Decoder, element, CLASS_ATTR)));

		if (className.empty())
		{
			logger->setLevel(OptionConverter::toLevel(levelStr, Level::getDebug()));
		}
		else
		{
			if (LogLog::isDebugEnabled())
			{
				LogLog::debug(LOG4CXX_STR("Desired ") + Level::getStaticClass().getName()
					+ LOG4CXX_STR(" sub-class: [") + className + LOG4CXX_STR("]"));
			}

			try
			{
				Level::LevelClass& levelClass =
					(Level::LevelClass&)Loader::loadClass(className);
				LevelPtr level = levelClass.toLevel(levelStr);
				logger->setLevel(level);
			}
			catch (Exception& oops)
			{
				LogLog::error(LOG4CXX_STR("Could not create ") + Level::getStaticClass().getName() + LOG4CXX_STR(" sub-class"), oops);
				return;
			}
			catch (...)
			{
				LogLog::error(LOG4CXX_STR("Could not create ") + Level::getStaticClass().getName() + LOG4CXX_STR(" sub-class")
							+ LOG4CXX_STR(" from [") + className
							+ LOG4CXX_STR("]"));
				return;
			}
		}
	}

	if (LogLog::isDebugEnabled())
	{
		LogLog::debug(LOG4CXX_STR("[") + loggerName + LOG4CXX_STR("] level is ") +
			logger->getEffectiveLevel()->toString());
	}
}

void DOMConfigurator::setParameter(LOG4CXX_NS::helpers::Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* elem,
	PropertySetter& propSetter)
{
	LogString name(subst(getAttribute(utf8Decoder, elem, NAME_ATTR)));
	LogString value(subst(getAttribute(utf8Decoder, elem, VALUE_ATTR)));
	value = subst(value);
	propSetter.setProperty(name, value, p);
}

spi::ConfigurationStatus DOMConfigurator::doConfigure
	( const File&                     filename
#if LOG4CXX_ABI_VERSION <= 15
	, spi::LoggerRepositoryPtr        repository
#else
	, const spi::LoggerRepositoryPtr& repository
#endif
	)
{
	m_priv->repository = repository ? repository : LogManager::getLoggerRepository();

#if LOG4CXX_ABI_VERSION <= 15
	m_priv->loggerFactory = std::make_shared<DefaultLoggerFactory>();
#else
	m_priv->loggerFactory = std::make_shared<LoggerFactory>();
#endif

	Pool p;
	apr_file_t* fd;

	log4cxx_status_t rv = filename.open(&fd, APR_READ, APR_OS_DEFAULT, p);

	if (rv != APR_SUCCESS)
	{
		LogLog::error(LOG4CXX_STR("Could not open configuration file [")
			+ filename.getPath() + LOG4CXX_STR("]")
			, IOException(rv));
		return spi::ConfigurationStatus::NotConfigured;
	}
	else
	{
		apr_xml_parser* parser = NULL;
		apr_xml_doc* doc = NULL;

		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("Loading configuration file [")
					+ filename.getPath() + LOG4CXX_STR("]"));
		}

		rv = apr_xml_parse_file(p.getAPRPool(), &parser, &doc, fd, 2000);

		if (rv != APR_SUCCESS)
		{
			LogString reason;
			if (parser)
			{
				char errbuf[2000];
				apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
				LOG4CXX_DECODE_CHAR(lsErrbuf, std::string(errbuf));
				reason.append(lsErrbuf);
			}
			else
			{
				char errbuf[2000];
				apr_strerror(rv, errbuf, sizeof(errbuf));
				LOG4CXX_DECODE_CHAR(lsErrbuf, std::string(errbuf));
				reason.append(lsErrbuf);
			}
			LogLog::error(LOG4CXX_STR("Error parsing file [")
				+ filename.getPath() + LOG4CXX_STR("]")
				, RuntimeException(reason));
			return spi::ConfigurationStatus::NotConfigured;
		}
		else
		{
			AppenderMap appenders;
			CharsetDecoderPtr utf8Decoder(CharsetDecoder::getUTF8Decoder());
			parse(p, utf8Decoder, doc->root, doc, appenders);
		}
	}

	if (!m_priv->appenderAdded)
	{
		LogLog::warn(LOG4CXX_STR("[") + filename.getPath()
			+ LOG4CXX_STR("] did not add an ") + Appender::getStaticClass().getName()
			+ LOG4CXX_STR(" to a logger"));
		return spi::ConfigurationStatus::NotConfigured;
	}

	m_priv->repository->setConfigured(true);
	return spi::ConfigurationStatus::Configured;
}

// Read configuration options from \c filename.
spi::ConfigurationStatus DOMConfigurator::configure(const File& filename)
{
	return DOMConfigurator().doConfigure(filename, LogManager::getLoggerRepository());
}

#if LOG4CXX_ABI_VERSION <= 15
spi::ConfigurationStatus DOMConfigurator::configure(const std::string& filename)
{
	File file(filename);
	return DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
}

#if LOG4CXX_WCHAR_T_API
spi::ConfigurationStatus DOMConfigurator::configure(const std::wstring& filename)
{
	File file(filename);
	return DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
}
#endif

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
spi::ConfigurationStatus DOMConfigurator::configure(const std::basic_string<UniChar>& filename)
{
	File file(filename);
	return DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
}
#endif

#if LOG4CXX_CFSTRING_API
spi::ConfigurationStatus DOMConfigurator::configure(const CFStringRef& filename)
{
	File file(filename);
	return DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
}
#endif


spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const std::string& filename)
{
	return configureAndWatch(filename, FileWatchdog::DEFAULT_DELAY);
}

#if LOG4CXX_WCHAR_T_API
spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const std::wstring& filename)
{
	return configureAndWatch(filename, FileWatchdog::DEFAULT_DELAY);
}
#endif

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const std::basic_string<UniChar>& filename)
{
	return configureAndWatch(filename, FileWatchdog::DEFAULT_DELAY);
}
#endif

#if LOG4CXX_CFSTRING_API
spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const CFStringRef& filename)
{
	return configureAndWatch(filename, FileWatchdog::DEFAULT_DELAY);
}
#endif

spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const std::string& filename, long delay)
{
	return configureAndWatch(File(filename), delay);
}
#endif // LOG4CXX_ABI_VERSION <= 15

spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const File& file, long delay)
{
	spi::ConfigurationStatus status = DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
	XMLWatchdog::startWatching(file, delay);
	return status;
}

#if LOG4CXX_ABI_VERSION <= 15
#if LOG4CXX_WCHAR_T_API
spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const std::wstring& filename, long delay)
{
	File file(filename);
	spi::ConfigurationStatus status = DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
	XMLWatchdog::startWatching(file, delay);
	return status;
}
#endif

#if LOG4CXX_UNICHAR_API || LOG4CXX_LOGCHAR_IS_UNICHAR
spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const std::basic_string<UniChar>& filename, long delay)
{
	File file(filename);
	spi::ConfigurationStatus status = DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
	XMLWatchdog::startWatching(file, delay);
	return status;
}
#endif

#if LOG4CXX_CFSTRING_API
spi::ConfigurationStatus DOMConfigurator::configureAndWatch(const CFStringRef& filename, long delay)
{
	File file(filename);
	spi::ConfigurationStatus status = DOMConfigurator().doConfigure(file, LogManager::getLoggerRepository());
	XMLWatchdog::startWatching(file, delay);
	return status;
}
#endif
#endif // LOG4CXX_ABI_VERSION <= 15

void DOMConfigurator::parse(
	Pool& p,
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* element,
	apr_xml_doc* doc,
	AppenderMap& appenders)
{
	std::string rootElementName(element->name);

	if (rootElementName != CONFIGURATION_TAG)
	{
		if (rootElementName == OLD_CONFIGURATION_TAG)
		{
			//LogLog::warn(LOG4CXX_STR("The <")+String(OLD_CONFIGURATION_TAG)+
			// LOG4CXX_STR("> element has been deprecated."));
			//LogLog::warn(LOG4CXX_STR("Use the <")+String(CONFIGURATION_TAG)+
			// LOG4CXX_STR("> element instead."));
		}
		else
		{
			LogString msg(LOG4CXX_STR("Root element ["));
			utf8Decoder->decode(element->name, MAX_ATTRIBUTE_NAME_LEN, msg);
			msg += LOG4CXX_STR("] is not [");
			utf8Decoder->decode(CONFIGURATION_TAG, MAX_ATTRIBUTE_NAME_LEN, msg);
			msg += LOG4CXX_STR("]");
			LogLog::error(msg);
			return;
		}
	}

	LogString debugAttrib = subst(getAttribute(utf8Decoder, element, INTERNAL_DEBUG_ATTR));

	// if the log4j.dtd is not specified in the XML file, then the
	// "debug" attribute is returned as the empty string.
	if (!debugAttrib.empty() && debugAttrib != LOG4CXX_STR("NULL"))
	{
		LogLog::setInternalDebugging(OptionConverter::toBoolean(debugAttrib, true));
	}

	LogString colorAttrib = subst(getAttribute(utf8Decoder, element, INTERNAL_COLOR_ATTR));
	if (!colorAttrib.empty())
	{
		LogLog::setColorEnabled(OptionConverter::toBoolean(colorAttrib, true));
	}

	LogString thresholdStr = subst(getAttribute(utf8Decoder, element, THRESHOLD_ATTR));

	if (!thresholdStr.empty() && thresholdStr != LOG4CXX_STR("NULL"))
	{
		m_priv->repository->setThreshold(OptionConverter::toLevel(thresholdStr, Level::getAll()));
		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("Repository threshold =[")
				+ m_priv->repository->getThreshold()->toString()
				+ LOG4CXX_STR("]"));
		}
	}

	std::string sAsyncAttr{ ASYNCHRONOUS_ATTR };
	auto lsAsynchronous = subst(getAttribute(utf8Decoder, element, sAsyncAttr));
	if (!lsAsynchronous.empty() && OptionConverter::toBoolean(lsAsynchronous, true))
	{
		LOG4CXX_DECODE_CHAR(lsAsyncAttr, sAsyncAttr);
		appenders[lsAsyncAttr] = std::make_shared<AsyncAppender>();
		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("Asynchronous logging =[")
				+ LogString(LOG4CXX_STR("true"))
				+ LOG4CXX_STR("]"));
		}
	}

	LogString threadSignalValue = subst(getAttribute(utf8Decoder, element, THREAD_CONFIG_ATTR));

	if ( !threadSignalValue.empty() && threadSignalValue != LOG4CXX_STR("NULL") )
	{
		if (LogLog::isDebugEnabled())
		{
			LogLog::debug(LOG4CXX_STR("ThreadUtility configuration =[") + threadSignalValue + LOG4CXX_STR("]"));
		}
		if ( threadSignalValue == LOG4CXX_STR("NoConfiguration") )
		{
			helpers::ThreadUtility::configure( ThreadConfigurationType::NoConfiguration );
		}
		else if ( threadSignalValue == LOG4CXX_STR("BlockSignalsOnly") )
		{
			helpers::ThreadUtility::configure( ThreadConfigurationType::BlockSignalsOnly );
		}
		else if ( threadSignalValue == LOG4CXX_STR("NameThreadOnly") )
		{
			helpers::ThreadUtility::configure( ThreadConfigurationType::NameThreadOnly );
		}
		else if ( threadSignalValue == LOG4CXX_STR("BlockSignalsAndNameThread") )
		{
			helpers::ThreadUtility::configure( ThreadConfigurationType::BlockSignalsAndNameThread );
		}
		else
		{
			LogLog::warn(LOG4CXX_STR("threadConfiguration value [") + threadSignalValue + LOG4CXX_STR("]") + LOG4CXX_STR(" is not valid"));
		}
	}

	apr_xml_elem* currentElement;

	for (currentElement = element->first_child;
		currentElement;
		currentElement = currentElement->next)
	{
		std::string tagName(currentElement->name);

		if (tagName == CATEGORY_FACTORY_TAG)
		{
			parseLoggerFactory(p, utf8Decoder, currentElement);
		}
	}

	for (currentElement = element->first_child;
		currentElement;
		currentElement = currentElement->next)
	{
		std::string tagName(currentElement->name);

		if (tagName == CATEGORY || tagName == LOGGER)
		{
			parseLogger(p, utf8Decoder, currentElement, doc, appenders);
		}
		else if (tagName == ROOT_TAG)
		{
			parseRoot(p, utf8Decoder, currentElement, doc, appenders);
		}
	}
}

LogString DOMConfigurator::subst(const LogString& value)
{
	try
	{
		return OptionConverter::substVars(value, m_priv->props);
	}
	catch (IllegalArgumentException& e)
	{
		LogLog::warn(LOG4CXX_STR("Could not substitute variables using [") + value + LOG4CXX_STR("]"), e);
		return value;
	}
}


LogString DOMConfigurator::getAttribute(
	LOG4CXX_NS::helpers::CharsetDecoderPtr& utf8Decoder,
	apr_xml_elem* element,
	const std::string& attrName)
{
	LogString attrValue;

	for (apr_xml_attr* attr = element->attr;
		attr;
		attr = attr->next)
	{
		if (attrName == attr->name)
		{
			utf8Decoder->decode(attr->value, MAX_ATTRIBUTE_NAME_LEN, attrValue);
		}
	}

	return attrValue;
}
