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

#if defined(_MSC_VER)
	#pragma warning ( disable: 4231 4251 4275 4786 )
#endif

#include <log4cxx/logstring.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/defaultloggerfactory.h>
#include <log4cxx/logger.h>
#include <log4cxx/spi/hierarchyeventlistener.h>
#include <log4cxx/level.h>
#include <algorithm>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/appender.h>
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/stringhelper.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/helpers/aprinitializer.h>
#include <log4cxx/defaultconfigurator.h>
#include <log4cxx/spi/rootlogger.h>
#include <mutex>
#include "assert.h"


using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(Hierarchy)

Hierarchy::Hierarchy() :
	pool(),
	loggers(new LoggerMap()),
	provisionNodes(new ProvisionNodeMap())
{
	std::unique_lock<std::mutex> lock(mutex);
	root = LoggerPtr(new RootLogger(pool, Level::getDebug()));
	defaultFactory = LoggerFactoryPtr(new DefaultLoggerFactory());
	emittedNoAppenderWarning = false;
	configured = false;
	thresholdInt = Level::ALL_INT;
	threshold = Level::getAll();
	emittedNoResourceBundleWarning = false;
}

Hierarchy::~Hierarchy()
{
	// TODO LOGCXX-430
	// https://issues.apache.org/jira/browse/LOGCXX-430?focusedCommentId=15175254&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-15175254
#ifndef APR_HAS_THREADS
	delete loggers;
	delete provisionNodes;
#endif
}

void Hierarchy::addHierarchyEventListener(const spi::HierarchyEventListenerPtr& listener)
{
	std::unique_lock<std::mutex> lock(mutex);

	if (std::find(listeners.begin(), listeners.end(), listener) != listeners.end())
	{
		LogLog::warn(LOG4CXX_STR("Ignoring attempt to add an existent listener."));
	}
	else
	{
		listeners.push_back(listener);
	}
}

void Hierarchy::clear()
{
	std::unique_lock<std::mutex> lock(mutex);
	loggers->clear();
}

void Hierarchy::emitNoAppenderWarning(const Logger* logger)
{
	bool emitWarning = false;
	{
		std::unique_lock<std::mutex> lock(mutex);
		emitWarning = !emittedNoAppenderWarning;
		emittedNoAppenderWarning = true;
	}

	// No appender in hierarchy, warn user only once.
	if (emitWarning)
	{
		LogLog::warn(((LogString) LOG4CXX_STR("No appender could be found for logger ("))
			+ logger->getName() + LOG4CXX_STR(")."));
		LogLog::warn(LOG4CXX_STR("Please initialize the log4cxx system properly."));
	}
}


LoggerPtr Hierarchy::exists(const LogString& name)
{
	std::unique_lock<std::mutex> lock(mutex);

	LoggerPtr logger;
	LoggerMap::iterator it = loggers->find(name);

	if (it != loggers->end())
	{
		logger = it->second;
	}


	return logger;
}

void Hierarchy::setThreshold(const LevelPtr& l)
{
	if (l != 0)
	{
		std::unique_lock<std::mutex> lock(mutex);
		setThresholdInternal(l);
	}
}

void Hierarchy::setThreshold(const LogString& levelStr)
{
	LevelPtr l(Level::toLevelLS(levelStr, 0));

	if (l != 0)
	{
		setThreshold(l);
	}
	else
	{
		LogLog::warn(((LogString) LOG4CXX_STR("No level could be found named \""))
			+ levelStr + LOG4CXX_STR("\"."));
	}
}

void Hierarchy::setThresholdInternal(const LevelPtr& l)
{
	thresholdInt = l->toInt();
	threshold = l;

	if (thresholdInt != Level::ALL_INT)
	{
		configured = true;
	}
}

void Hierarchy::fireAddAppenderEvent(const Logger* logger, const Appender* appender)
{
	setConfigured(true);
	HierarchyEventListenerList clonedList;
	{
		std::unique_lock<std::mutex> lock(mutex);
		clonedList = listeners;
	}

	HierarchyEventListenerList::iterator it, itEnd = clonedList.end();
	HierarchyEventListenerPtr listener;

	for (it = clonedList.begin(); it != itEnd; it++)
	{
		listener = *it;
		listener->addAppenderEvent(logger, appender);
	}
}

void Hierarchy::fireRemoveAppenderEvent(const Logger* logger, const Appender* appender)

{
	HierarchyEventListenerList clonedList;
	{
		std::unique_lock<std::mutex> lock(mutex);
		clonedList = listeners;
	}
	HierarchyEventListenerList::iterator it, itEnd = clonedList.end();
	HierarchyEventListenerPtr listener;

	for (it = clonedList.begin(); it != itEnd; it++)
	{
		listener = *it;
		listener->removeAppenderEvent(logger, appender);
	}
}

const LevelPtr& Hierarchy::getThreshold() const
{
	return threshold;
}

LoggerPtr Hierarchy::getLogger(const LogString& name)
{
	return getLogger(name, defaultFactory);
}

LoggerPtr Hierarchy::getLogger(const LogString& name,
	const spi::LoggerFactoryPtr& factory)
{
	std::unique_lock<std::mutex> lock(mutex);

	LoggerMap::iterator it = loggers->find(name);

	if (it != loggers->end())
	{
		return it->second;
	}
	else
	{
		LoggerPtr logger(factory->makeNewLoggerInstance(pool, name));
		logger->setHierarchy(weak_from_this());
		loggers->insert(LoggerMap::value_type(name, logger));

		ProvisionNodeMap::iterator it2 = provisionNodes->find(name);

		if (it2 != provisionNodes->end())
		{
			updateChildren(it2->second, logger);
			provisionNodes->erase(it2);
		}

		updateParents(logger);
		return logger;
	}

}

LoggerList Hierarchy::getCurrentLoggers() const
{
	std::unique_lock<std::mutex> lock(mutex);

	LoggerList v;
	LoggerMap::const_iterator it, itEnd = loggers->end();

	for (it = loggers->begin(); it != itEnd; it++)
	{
		v.push_back(it->second);
	}


	return v;
}

LoggerPtr Hierarchy::getRootLogger() const
{
	return root;
}

bool Hierarchy::isDisabled(int level) const
{
	bool currentlyConfigured;
	{
		std::unique_lock<std::mutex> lock(mutex);
		currentlyConfigured = configured;
	}

	if (!currentlyConfigured)
	{
		std::shared_ptr<Hierarchy> nonconstThis = std::const_pointer_cast<Hierarchy>(shared_from_this());
		DefaultConfigurator::configure(
			nonconstThis);
	}

	return thresholdInt > level;
}


void Hierarchy::resetConfiguration()
{
	std::unique_lock<std::mutex> lock(mutex);

	getRootLogger()->setLevel(Level::getDebug());
	root->setResourceBundle(0);
	setThresholdInternal(Level::getAll());

	shutdownInternal();

	LoggerMap::const_iterator it, itEnd = loggers->end();

	for (it = loggers->begin(); it != itEnd; it++)
	{
		it->second->setLevel(0);
		it->second->setAdditivity(true);
		it->second->setResourceBundle(0);
	}

	//rendererMap.clear();
}

void Hierarchy::shutdown()
{
	std::unique_lock<std::mutex> lock(mutex);

	shutdownInternal();
}

void Hierarchy::shutdownInternal()
{
	configured = false;

	LoggerPtr root1 = getRootLogger();

	// begin by closing nested appenders
	root1->closeNestedAppenders();

	LoggerMap::iterator it, itEnd = loggers->end();

	for (it = loggers->begin(); it != itEnd; it++)
	{
		LoggerPtr logger = it->second;
		logger->closeNestedAppenders();
	}

	// then, remove all appenders
	root1->removeAllAppenders();

	for (it = loggers->begin(); it != itEnd; it++)
	{
		LoggerPtr logger = it->second;
		logger->removeAllAppenders();
	}
}

void Hierarchy::updateParents(LoggerPtr logger)
{
	const LogString name(logger->getName());
	size_t length = name.size();
	bool parentFound = false;


	// if name = "w.x.y.z", loop through "w.x.y", "w.x" and "w", but not "w.x.y.z"
	for (size_t i = name.find_last_of(0x2E /* '.' */, length - 1);
		(i != LogString::npos) && (i != 0);
		i = name.find_last_of(0x2E /* '.' */, i - 1))
	{
		LogString substr = name.substr(0, i);

		LoggerMap::iterator it = loggers->find(substr);

		if (it != loggers->end())
		{
			parentFound = true;
			logger->parent = it->second;
			break; // no need to update the ancestors of the closest ancestor
		}
		else
		{
			ProvisionNodeMap::iterator it2 = provisionNodes->find(substr);

			if (it2 != provisionNodes->end())
			{
				it2->second.push_back(logger);
			}
			else
			{
				ProvisionNode node(1, logger);
				provisionNodes->insert(
					ProvisionNodeMap::value_type(substr, node));
			}
		}
	}

	// If we could not find any existing parents, then link with root.
	if (!parentFound)
	{
		logger->parent = root;
	}
}

void Hierarchy::updateChildren(ProvisionNode& pn, LoggerPtr logger)
{

	ProvisionNode::iterator it, itEnd = pn.end();

	for (it = pn.begin(); it != itEnd; it++)
	{
		LoggerPtr& l = *it;

		// Unless this child already points to a correct (lower) parent,
		// make cat.parent point to l.parent and l.parent to cat.
		if (!StringHelper::startsWith(l->parent->name, logger->name))
		{
			logger->parent = l->parent;
			l->parent = logger;
		}
	}
}

void Hierarchy::setConfigured(bool newValue)
{
	std::unique_lock<std::mutex> lock(mutex);
	configured = newValue;
}

bool Hierarchy::isConfigured()
{
	return configured;
}

HierarchyPtr Hierarchy::create(){
	HierarchyPtr ret( new Hierarchy() );
	ret->configureRoot();
	return ret;
}

void Hierarchy::configureRoot(){
	// This should really be done in the constructor, but in order to fix
	// LOGCXX-322 we need to turn the repositroy into a weak_ptr, and we
	// can't use weak_from_this() in the constructor.
	if( !root->getLoggerRepository().lock() ){
		root->setHierarchy(weak_from_this());
	}
}
