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


#if !defined(_LOG4CXX_ROLLING_TRIGGER_POLICY_H)
#define _LOG4CXX_ROLLING_TRIGGER_POLICY_H


#include <log4cxx/helpers/object.h>

namespace log4cxx {
    class File;
    namespace rolling {

        /**
         * A <code>TriggeringPolicy</code> controls the conditions under which rollover
         * occurs. Such conditions include time od day, file size, an 
         * external event or a combination thereof.
         *
         * @author Ceki G&uuml;lc&uuml;
         * @since 1.3
         * */

        class LOG4CXX_EXPORT TriggeringPolicy : public log4cxx::helpers::Object  {
  
          /**
           * Should rolllover be triggered at this time?
           * 
           * @param file A reference to the currently active log file. 
           * */
           virtual bool isTriggeringEvent(const log4cxx::File& file) = 0;
        };

        typedef log4cxx::helpers::ObjectPtrT<TriggeringPolicy> TriggeringPolicyPtr;

    }
}

#endif
