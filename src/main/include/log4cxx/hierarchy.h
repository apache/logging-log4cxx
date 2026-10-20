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

#ifndef _LOG4CXX_HIERARCHY_H
#define _LOG4CXX_HIERARCHY_H


#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/spi/loggerfactory.h>
#include <log4cxx/provisionnode.h>
#include <log4cxx/spi/hierarchyeventlistener.h>

namespace LOG4CXX_NS
{

class Hierarchy;
LOG4CXX_PTR_DEF(Hierarchy);

/**
This class is specialized in retrieving loggers by name and also
maintaining the logger hierarchy.

<p><em>The casual user does not have to deal with this class
directly.</em>

<p>The structure of the logger hierarchy is maintained by the
#getLogger method. The hierarchy is such that children link
to their parent but parents do not have any pointers to their
children. Moreover, loggers can be instantiated in any order, in
particular descendant before ancestor.

<p>In case a descendant is created before a particular ancestor,
then it creates a provision node for the ancestor and adds itself
to the provision node. Other descendants of the same ancestor add
themselves to the previously created provision node.
*/
class LOG4CXX_EXPORT Hierarchy : public spi::LoggerRepository
{
	private:
		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(HierarchyPrivate, m_priv)

	public:
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Hierarchy)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Hierarchy)
		LOG4CXX_CAST_ENTRY_CHAIN(spi::LoggerRepository)
		END_LOG4CXX_CAST_MAP()

	private:
		/**
		An empty logger hierarchy.
		*/
		Hierarchy();

	public:
		/**
		Create a new logger hierarchy.
		*/
		static HierarchyPtr create();

		~Hierarchy();

		/** {@inheritDoc}
		*/
		void addHierarchyEventListener(const spi::HierarchyEventListenerPtr& listener) override;

		/** {@inheritDoc}
		*/
		void removeHierarchyEventListener(const spi::HierarchyEventListenerPtr& listener) override;

		/** {@inheritDoc}
		*/
		void ensureIsConfigured(std::function<void()> configurator) override;

		/**
		This call will clear all logger definitions from the internal
		hashtable. Invoking this method will irrevocably mess up the
		logger hierarchy.

		<p>You should <em>really</em> know what you are doing before
		invoking this method.
		*/
		void clear();

		void emitNoAppenderWarning(const Logger* logger) override;

		/** {@inheritDoc}
		*/
		LoggerPtr exists(const LogString& name) override;

		/** {@inheritDoc}
		*/
		void setThreshold(const LogString& levelStr) override;

		/** {@inheritDoc}
		*/
		void setThreshold(const LevelPtr& newLevel) override;

		/** {@inheritDoc}
		*/
		void fireAddAppenderEvent(const Logger* logger, const Appender* appender) override;

		/** {@inheritDoc}
		*/
		void fireRemoveAppenderEvent(const Logger* logger, const Appender* appender) override;

		/** {@inheritDoc}
		*/
		LevelPtr getThreshold() const override;

		/** {@inheritDoc}
		*/
		LoggerPtr getLogger(const LogString& name,
			const spi::LoggerFactoryPtr& factory = {}) override;

		/** {@inheritDoc}
		*/
		LoggerList getCurrentLoggers() const override;

		/** {@inheritDoc}
		*/
		LoggerPtr getRootLogger() const override;

		/** {@inheritDoc}
		*/
		bool isDisabled(int level) const override;

		/** {@inheritDoc}
		*/
		void resetConfiguration() override;

		/**
		Shutting down a hierarchy will <em>safely</em> close and remove
		all appenders in all categories including the root logger.

		<p>The <code>shutdown</code> method is careful to close nested
		appenders before closing regular appenders. This is allows
		configurations where a regular appender is attached to a logger
		and again to a nested appender.
		*/
		void shutdown() override;

		/** {@inheritDoc}
		*/
		virtual bool isConfigured() override;

		/** {@inheritDoc}
		*/
		virtual void setConfigured(bool configured) override;

		/** {@inheritDoc}
		*/
		void updateChildren(const Logger* parent) override;

		/** {@inheritDoc}
		*/
		bool removeLogger(const LogString& name, bool ifNotUsed = true) override;

	private:

		/**
		 * Set the threshold.  The mutex must already be locked.
		 */
		void setThresholdInternal(const LevelPtr& l);

		/**
		 * Internal shutdown.  The mutex must already be locked.
		 */
		void shutdownInternal();

		/**
		This method loops through all the *potential* parents of
		\c logger using the logger name.
		For example, for a logger named "w.x.y.z",
		loop through "w.x.y", "w.x" and "w", but not "w.x.y.z".
		There 3 possible cases:

		1) No entry for the potential parent of "w.x.y.z" exists

		We create a ProvisionNode for this potential parent and insert
		"w.x.y.z" in that provision node.

		2) There entry is of type Logger for the potential parent.

		The entry is "w.x.y.z"'s nearest existing parent. We update "w.x.y.z"'s
		parent field with this entry. We also break from the loop
		because updating our parent's parent is our parent's
		responsibility.

		3) There entry is of type ProvisionNode for this potential parent.

		We add "w.x.y.z" to the list of children for this potential parent.
		*/
		void updateParents(const LoggerPtr& logger, const LoggerPtr& root);

		/**
		Refresh the \c pn parent links for entries
		whose name includes \c logger's name as a prefix.
		The newly created \c logger is a potential parent of a provisional logger.
		The parent of the matched provisional entry becomes the parent of \c logger
		and \c logger becomes the parent of the matched provisional entry.

		\sa updateParents()
		*/
		void updateAncestory(ProvisionNode& pn, const LoggerPtr& logger);

		Hierarchy(const Hierarchy&);
		Hierarchy& operator=(const Hierarchy&);

};

}  //namespace log4cxx

#endif //_LOG4CXX_HIERARCHY_H
