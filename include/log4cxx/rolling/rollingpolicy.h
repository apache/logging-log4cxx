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

#if !defined(_LOG4CXX_ROLLING_ROLLING_POLICY_H)
#define _LOG4CXX_ROLLING_ROLLING_POLICY_H

#include <log4cxx/portability.h>
#include <log4cxx/spi/optionhandler.h>
#include <log4cxx/file.h>

namespace log4cxx {
    namespace rolling {


        /**
         * A <code>RollingPolicy</code> is responsible for performing the
         * rolling over of the active log file. The <code>RollingPolicy</code>
         * is also responsible for providing the <em>active log file</em>,
         * that is the live file where logging output will be directed.
         * 
         * @author Ceki G&uuml;lc&uuml;
         * @since 1.3
         * 
        */
        class LOG4CXX_EXPORT RollingPolicy : public log4cxx::spi::OptionHandler {
        public:
  
              /**
               * Rolls over log files according to implementation policy.  
               * <p>
               * <p>This method is invoked by {@link RollingFileAppender}, usually 
               * at the behest of its {@link TriggeringPolicy}.
               * 
               * @throws RolloverFailure Thrown if the rollover operation fails for any
               * reason.
               */
              virtual void rollover() = 0;

              /**
               * Get the new name of the active log file.
               * */  
              virtual log4cxx::File getActiveFileName() = 0;
        };

        typedef log4cxx::helpers::ObjectPtrT<RollingPolicy> RollingPolicyPtr;

    }
}
#endif

