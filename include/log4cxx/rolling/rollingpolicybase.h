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

#if !defined(_LOG4CXX_ROLLING_ROLLING_POLICY_BASE_H)
#define _LOG4CXX_ROLLING_ROLLING_POLICY_BASE_H

#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/rolling/rollingpolicy.h>

namespace log4cxx {
    namespace rolling {

         typedef LogString FileNamePattern;

        /**
         * Implements methods common to most, it not all, rolling
         * policies. Currently such methods are limited to a compression mode
         * getter/setter.
         *
         * @author Ceki G&uuml;lc&uuml;
         * @since 1.3
         */
        class RollingPolicyBase : public virtual RollingPolicy,
            public virtual log4cxx::helpers::ObjectImpl
        {
        protected:
          int compressionMode;
          FileNamePattern fileNamePattern;
          LogString fileNamePatternStr;
          File activeFileName;

        public:
        BEGIN_LOG4CXX_CAST_MAP()
                LOG4CXX_CAST_ENTRY(RollingPolicyBase)
                LOG4CXX_CAST_ENTRY(spi::OptionHandler)
        END_LOG4CXX_CAST_MAP()



        virtual void activateOptions(log4cxx::helpers::Pool& pool) {}
        virtual void setOption(const LogString& option, const LogString& value);

        protected:

          /**
           * Given the FileNamePattern string, this method determines the compression
           * mode depending on last letters of the fileNamePatternStr. Patterns
           * ending with .gz imply GZIP compression, endings with '.zip' imply
           * ZIP compression. Otherwise and by default, there is no compression.
           *
           */
          void determineCompressionMode();

        public:

          void setFileNamePattern(const LogString& fnp);

          LogString getFileNamePattern() const;

          /**
           * ActiveFileName can be left unset, i.e. as null.
           * @see #getActiveFileName
           */
          void setActiveFileName(const File& afn);

        };
    }
}


#endif
