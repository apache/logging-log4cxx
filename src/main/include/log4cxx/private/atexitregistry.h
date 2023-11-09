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

#ifndef _LOG4CXX_HELPERS_AT_EXIT_REGISTRY_H
#define _LOG4CXX_HELPERS_AT_EXIT_REGISTRY_H

#include <log4cxx/log4cxx.h>
#include <functional>

#if !LOG4CXX_EVENTS_AT_EXIT
	#error atexitregistry.h should only be included if LOG4CXX_EVENTS_AT_EXIT is set
#endif

namespace LOG4CXX_NS
{
namespace helpers
{
	
/* 
 * Provides the initiation of the minimum necessary actions (buffers flushing for example) at the static deinitialization phase.
 */
class LOG4CXX_EXPORT AtExitRegistry
{
public:
	struct Raii
	{
		Raii(std::function<void()> action)
		{
			AtExitRegistry::instance().add(this, std::move(action));
		}
		
		~Raii()
		{
			AtExitRegistry::instance().del(this);
		}
		
		Raii(const Raii&) = delete;
		void operator=(const Raii&) = delete;
	};
	
private:
	friend Raii;
	static AtExitRegistry& instance();
	void add(void* key, std::function<void()> action);
	void del(void* key);
};
}
}

#endif
