/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LOG4CXX_PRIV_MUTEX_HDR_
#define LOG4CXX_PRIV_MUTEX_HDR_
#include <mutex>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>

namespace log4cxx
{

using AppenderMutexType = std::mutex;
using AppenderScopeGuard = std::lock_guard<AppenderMutexType>;
using AppenderScopedLock = std::unique_lock<AppenderMutexType>;

// Change mutex attributes to avoid priority inversion problems
template <class M>
	void
EnablePriorityInheritance(M& m, helpers::Pool& p)
{
#if LOG4CXX_HAS_PTHREAD_SETPROTOCOL
	pthread_mutexattr_t rrAttr;
	if (pthread_mutexattr_init(&rrAttr) != 0)
	{
		LogString msg = LOG4CXX_STR("pthread_mutexattr_init error ");
		helpers::toString(errno, p, msg)
		helpers::LogLog::warn(msg);
	}
	else if (pthread_mutexattr_setprotocol(&rrAttr, PTHREAD_PRIO_INHERIT) != 0)
	{
		LogString msg = LOG4CXX_STR("pthread_mutexattr_setprotocol error ");
		helpers::toString(errno, p, msg)
		helpers::LogLog::warn(msg);
	}
	else if (pthread_mutex_destroy(m.native_handle()) != 0)
	{
		LogString msg = LOG4CXX_STR("pthread_mutex_destroy error ");
		helpers::toString(errno, p, msg)
		helpers::LogLog::warn(msg);
	}
	else if (pthread_mutex_init(m.native_handle(), &rrAttr) != 0)
	{
		LogString msg = LOG4CXX_STR("pthread_mutex_init error ");
		helpers::toString(errno, p, msg)
		helpers::LogLog::warn(msg);
	}
	pthread_mutexattr_destroy(&rrAttr);
#endif // LOG4CXX_HAS_PTHREAD_SETPROTOCOL
}

} // namespace log4cxx

#endif /* LOG4CXX_PRIV_MUTEX_HDR_ */
