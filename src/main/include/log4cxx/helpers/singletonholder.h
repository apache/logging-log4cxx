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

#ifndef LOG4CXX_SINGLETON_HOLDER_H
#define LOG4CXX_SINGLETON_HOLDER_H

#include <log4cxx/helpers/object.h>

namespace LOG4CXX_NS
{
namespace helpers
{

/** Wraps any singleton object so it can be added to APRInitializer
 */
template <class T>
class SingletonHolder : public Object
{
	using ThisType = SingletonHolder<T>;
	T m_data;
	struct Unused : public helpers::Class
	{
		LogString getName() const override { return LOG4CXX_STR("SingletonHolder"); }
	};
public: // Object method stubs
	const helpers::Class& getClass() const override { static Unused notUsed; return notUsed; }
	BEGIN_LOG4CXX_CAST_MAP()
	LOG4CXX_CAST_ENTRY(ThisType)
	END_LOG4CXX_CAST_MAP()

public: // Accessors
	T& value() { return m_data; }
};

} // namespace helpers
} // namespace LOG4CXX_NS

#endif //LOG4CXX_SINGLETON_HOLDER_H
