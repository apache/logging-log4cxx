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

#include "num343patternconverter.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::pattern;

IMPLEMENT_LOG4CXX_OBJECT(Num343PatternConverter)


Num343PatternConverter::Num343PatternConverter() {
}

PatternConverter* Num343PatternConverter::newInstance(
   const FormattingInfo&,
   const std::vector<LogString>&) {
   return new Num343PatternConverter();
}


void Num343PatternConverter::convert(LogString& sbuf,
    const spi::LoggingEventPtr&,
    Pool&) const
{
        sbuf.append(LOG4CXX_STR("343"));
}

