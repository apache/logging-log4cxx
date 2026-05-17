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

#if !defined(_LOG4CXX_ROLLING_ACTION_H)
#define _LOG4CXX_ROLLING_ACTION_H

#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/pool.h>

namespace LOG4CXX_NS
{
namespace rolling
{


/**
 *  A file system action performed as part of a rollover event.
 */
class Action : public virtual LOG4CXX_NS::helpers::Object
{
		DECLARE_ABSTRACT_LOG4CXX_OBJECT(Action)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(Action)
		END_LOG4CXX_CAST_MAP()

		LOG4CXX_DECLARE_PRIVATE_MEMBER_PTR(ActionPrivate, m_priv)

	protected:
		/**
		 * Constructor.
		 */
		Action();
		Action(LOG4CXX_PRIVATE_PTR(ActionPrivate) priv);
		virtual ~Action();

	public:
		/**
		 * Perform the action.
		 *
		 * @return true if successful.
		 */
#if LOG4CXX_ABI_VERSION <= 15
		bool execute() const;
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		Implement this method for now, but plan to migrate to execute() without a helpers::Pool parameter.
		*/
		virtual bool execute(helpers::Pool& pool) const = 0;
#define LOG4CXX_EXECUTE_ACTION_FORMAL_PARAMETERS helpers::Pool& p
#else
		virtual bool execute() const = 0;
#define LOG4CXX_EXECUTE_ACTION_FORMAL_PARAMETERS
		/**
		@deprecated The \c pool parameter is not used and will be removed in a future version.
		*/
		[[deprecated("Use execute() without a Pool parameter instead")]]
		bool execute(helpers::Pool& pool) const;
#endif

		/* Call execute() if not already closed.
		*/
		void run();

		/* Wait until run() completes.
		*/
		void close();

		/**
		 * Is action is complete?
		 */
		bool isComplete() const;

		/* The action description
		*/
		LogString getName() const;

#if LOG4CXX_ABI_VERSION <= 15
		void reportException(const std::exception&);

		void run(helpers::Pool& pool);
#endif

};

LOG4CXX_PTR_DEF(Action);

}
}
#endif

