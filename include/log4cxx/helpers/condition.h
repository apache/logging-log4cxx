/*
 * Copyright 2003,2004 The Apache Software Foundation.
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
 
#ifndef _LOG4CXX_HELPERS_CONDITION_H
#define _LOG4CXX_HELPERS_CONDITION_H

#include <log4cxx/helpers/exception.h>


struct apr_pool_t;
struct apr_thread_cond_t;
struct apr_thread_mutex_t;

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT ConditionException : public Exception
		{
		public:
			ConditionException(log4cxx_status_t stat) {}
		};

		class LOG4CXX_EXPORT Condition
		{
		public:
			Condition(apr_pool_t* p);
			~Condition();
			void broadcast();
			void wait();

		private:
			apr_thread_cond_t* condition;
			apr_thread_mutex_t* mutex;
		};
	} // namespace helpers
};// namespace log4cxx

#endif //_LOG4CXX_HELPERS_CONDITION_H
