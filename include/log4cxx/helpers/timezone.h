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

#ifndef _LOG4CXX_HELPERS_TIMEZONE_H
#define _LOG4CXX_HELPERS_TIMEZONE_H

#include <log4cxx/portability.h>
#include <log4cxx/helpers/tchar.h>
#include <log4cxx/helpers/objectimpl.h>
#include <log4cxx/helpers/objectptr.h>

namespace log4cxx
{
	namespace helpers
	{
		class TimeZone;
		typedef helpers::ObjectPtrT<TimeZone> TimeZonePtr;

		class LOG4CXX_EXPORT TimeZone : public helpers::ObjectImpl
		{
		public:
			DECLARE_ABSTRACT_LOG4CXX_OBJECT(TimeZone)
			BEGIN_LOG4CXX_CAST_MAP()
				LOG4CXX_CAST_ENTRY(TimeZone)
			END_LOG4CXX_CAST_MAP()

			static const TimeZonePtr& getDefault();
                        static const TimeZonePtr& getGMT();
			static const TimeZonePtr getTimeZone(const String& ID);

                        const String getID() const {
                          return id;
                        }


                        /**
                         *   Expand an APR time into the human readable
                         *      components for this timezone.
                         */
                        virtual apr_status_t explode(apr_time_exp_t* result,
                                                     apr_time_t input) const = 0;


		protected:
                       TimeZone(const String& ID);
                       virtual ~TimeZone();

                       const String id;
		};


	}
}

#endif //_LOG4CXX_HELPERS_TIMEZONE_H
