/*
 * Copyright 1999,2004 The Apache Software Foundation.
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

#ifndef _LOG4CXX_HELPER_NAMED_PATTERN_CONVERTER_H
#define _LOG4CXX_HELPER_NAMED_PATTERN_CONVERTER_H

#include <log4cxx/helpers/patternconverter.h>
#include <vector>

namespace log4cxx {
    namespace helpers {
        /**
         * 
         * Base class for other pattern converters which can return only parts of their name.
         *  
         * @author Ceki G&uuml;lc&uuml;
         * @author Curt Arnold
         */
        class NamedPatternConverter : public PatternConverter {
        private:
          int precision;
        public:
          DECLARE_ABSTRACT_LOG4CXX_OBJECT(NamedPatternConverter)
          BEGIN_LOG4CXX_CAST_MAP()
                LOG4CXX_CAST_ENTRY(NamedPatternConverter)
          END_LOG4CXX_CAST_MAP()

          NamedPatternConverter();
          NamedPatternConverter(const FormattingInfo& fi, const std::vector<LogString>& options);
          virtual void setOptions(const std::vector<LogString>& options);

        protected:
            /**
             *  PatternConverter's virtual method.
             *
             */
            virtual void convert(LogString& sbuf,
                const log4cxx::spi::LoggingEventPtr& event,
                    log4cxx::helpers::Pool& pool) const;

            virtual LogString getFullyQualifiedName(const log4cxx::spi::LoggingEventPtr& event) const = 0;

        };
    }
}

#endif
