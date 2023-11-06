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
#include <log4cxx/private/atexitregistry.h>
#include <mutex>
#include <map>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

namespace
{
	struct AtExitRegistryImpl : public AtExitRegistry
	{
		~AtExitRegistryImpl()
		{
			std::lock_guard<std::recursive_mutex> lock(mutex);
			while(!actions.empty())
			{
				std::function<void()> action = std::move(actions.begin()->second);
				actions.erase(actions.begin());
				action();
			}
		}

		void add(void* key, std::function<void()> action)
		{
			std::lock_guard<std::recursive_mutex> lock(mutex);
			actions.emplace(key, std::move(action));
		}

		void del(void* key)
		{
			std::lock_guard<std::recursive_mutex> lock(mutex);
			actions.erase(key);
		}

	private:
		std::recursive_mutex mutex;
		std::map<void*, std::function<void()>> actions;
	} s_instance;
}

AtExitRegistry& AtExitRegistry::instance()
{
	return s_instance;
}

void AtExitRegistry::add(void* key, std::function<void()> action)
{
	return s_instance.add(key, std::move(action));
}

void AtExitRegistry::del(void* key)
{
	return s_instance.del(key);
}

