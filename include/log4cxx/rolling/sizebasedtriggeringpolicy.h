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

#if !defined(_LOG4CXX_ROLLING_SIZE_BASED_TRIGGERING_POLICY_H)
#define _LOG4CXX_ROLLING_SIZE_BASED_TRIGGERING_POLICY_H

#include <log4cxx/rolling/triggeringpolicy.h>

namespace log4cxx {

    class File;

    namespace rolling {

        /**
         * SizeBasedTriggeringPolicy looks at size of the file being
         * currently written to.
         *
         * @author Ceki G&uuml;lc&uuml;
         *
         */
        class LOG4CXX_EXPORT SizeBasedTriggeringPolicy : public TriggeringPolicy {
        protected:
          long maxFileSize;

        public:
            bool isTriggeringEvent(const log4cxx::File& file);

            size_t getMaxFileSize();

            void setMaxFileSize(size_t l);

            void activateOptions();
        };

        typedef log4cxx::helpers::ObjectPtrT<SizeBasedTriggeringPolicy> SizeBasedTriggeringPolicyPtr;

    }
}
#endif

