/*
 * Copyright 2003,2005 The Apache Software Foundation.
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

#include <log4cxx/helpers/patternconverter.h>
#include <vector>

namespace log4cxx
{
   namespace pattern {
     class Num343PatternConverter : public log4cxx::helpers::PatternConverter
     {
     public:
       Num343PatternConverter();
       static log4cxx::helpers::PatternConverter* newInstance(
          const log4cxx::helpers::FormattingInfo& info,
          const std::vector<LogString>& options);

     protected:
     virtual void convert(LogString& sbuf,
              const log4cxx::spi::LoggingEventPtr& event,
              log4cxx::helpers::Pool& pool) const;
     };
   }
}
