/*
 * Copyright 1999,2005 The Apache Software Foundation.
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

#if !defined(_LOG4CXX_ROLLING_ROLLOVER_FAILURE_H)
#define _LOG4CXX_ROLLING_ROLLOVER_FAILURE_H

#include <log4cxx/helpers/exception.h>

namespace log4cxx {
    namespace rolling {

        /**
         * A RolloverFailure occurs if, for whatever reason a rollover fails.
         *
         * @author Ceki Gulcu
         */
        class LOG4CXX_EXPORT RolloverFailure : public log4cxx::helpers::Exception {
        public:
          RolloverFailure(const LogString& msg);
          RolloverFailure(const RolloverFailure& src);
          RolloverFailure& operator=(const RolloverFailure& src);
        };
    }
}


#endif
