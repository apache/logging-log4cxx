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
 
#ifndef _LOG4CXX_HELPERS_THREAD_SPECIFIC_DATA_H
#define _LOG4CXX_HELPERS_THREAD_SPECIFIC_DATA_H

#include <log4cxx/portability.h>
#include <memory>

namespace log4cxx
{
	namespace helpers
	{
		class LOG4CXX_EXPORT ThreadSpecificData
		{
		public:
			ThreadSpecificData();
			ThreadSpecificData(void (*cleanup)(void*));
			~ThreadSpecificData();
			void * GetData() const;
			void SetData(void * data);

		protected:
			struct Impl;
			std::auto_ptr<Impl> impl;
		};

		template < typename T >
			class ThreadSpecificData_ptr
			{
			public:
				ThreadSpecificData_ptr(T * p = 0): impl(&cleanup)
				{
					reset(p);
				}

				T * get() const
				{
					return static_cast<T*>( impl.GetData() );
				}

				void reset(T * p)
				{
					T * tmp = get();
					if(tmp)
						delete tmp;
					impl.SetData(p);
				}

				operator T * () const
				{
					return get();
				}

				T * operator->() const
				{
					return get();
				}

				T & operator*() const
				{
					return *get();
				}

				T * release()
				{
					T * tmp = get();
					impl.SetData(0);
					return tmp;
				}
				
			private:
				ThreadSpecificData impl;
				static void cleanup(void * p)
				{
					delete static_cast<T*>(p);
				}
			};
	}  // namespace helpers
}; // namespace log4cxx

#endif
