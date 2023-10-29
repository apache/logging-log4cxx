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
#include <log4cxx/layout.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(Layout)


Layout::~Layout() {}

LogString Layout::getContentType() const
{
	return LOG4CXX_STR("text/plain");
}

void Layout::appendHeader(LogString&, LOG4CXX_NS::helpers::Pool&) {}

void Layout::appendFooter(LogString&, LOG4CXX_NS::helpers::Pool&) {}

/**
 * The expected length of a formatted event excluding the message text
 */
size_t Layout::getFormattedEventCharacterCount() const
{
	auto exampleEvent = std::make_shared<spi::LoggingEvent>
		( LOG4CXX_STR("example.logger")
		, Level::getDebug()
		, LOG4CXX_LOCATION
		, LogString()
		);
	LogString text;
	Pool pool;
	format(text, exampleEvent, pool);
	return text.size();
}
