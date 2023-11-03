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
#include <log4cxx/pattern/ndcpatternconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/location/locationinfo.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::pattern;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(NDCPatternConverter)

NDCPatternConverter::NDCPatternConverter() :
	LoggingEventPatternConverter(LOG4CXX_STR("NDC"),
		LOG4CXX_STR("ndc"))
{
}

PatternConverterPtr NDCPatternConverter::newInstance(
	const std::vector<LogString>& /* options */)
{
	static WideLife<PatternConverterPtr> def = std::make_shared<NDCPatternConverter>();
	return def;
}

void NDCPatternConverter::format(
	const LoggingEventPtr& event,
	LogString& toAppendTo,
	Pool& /* p */) const
{
	if (!event->getNDC(toAppendTo))
	{
		toAppendTo.append(LOG4CXX_STR("null"));
	}
}
