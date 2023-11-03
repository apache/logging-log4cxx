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
#include <mutex>
#include <memory>

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
		 * Perform action.
		 *
		 * @return true if successful.
		 */
		virtual bool execute(LOG4CXX_NS::helpers::Pool& pool) const = 0;

		void run(LOG4CXX_NS::helpers::Pool& pool);

		void close();

		/**
		 * Tests if the action is complete.
		 * @return true if action is complete.
		 */
		bool isComplete() const;

		void reportException(const std::exception&);


};

LOG4CXX_PTR_DEF(Action);

}
}
#endif

