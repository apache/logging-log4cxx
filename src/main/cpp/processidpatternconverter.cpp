/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <log4cxx/logstring.h>
#include <log4cxx/pattern/processidpatternconverter.h>
#include <log4cxx/helpers/stringhelper.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::pattern;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(ProcessIdPatternConverter)

ProcessIdPatternConverter::ProcessIdPatternConverter() :
	LoggingEventPatternConverter(LOG4CXX_STR("Process Id"),
		LOG4CXX_STR("processId"))
{
}

PatternConverterPtr ProcessIdPatternConverter::newInstance(
	const std::vector<LogString>& /* options */)
{
	return std::make_shared<ProcessIdPatternConverter>();
}

void ProcessIdPatternConverter::format( const spi::LoggingEventPtr& /* event */, LogString& toAppendTo ) const
{
#if defined(_WIN32)
	auto pid = static_cast<int64_t>(GetCurrentProcessId());
#else
	auto pid = static_cast<int64_t>(getpid());
#endif
	StringHelper::toString(pid, toAppendTo);
}
