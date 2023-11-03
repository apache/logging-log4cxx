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
#include <log4cxx/pattern/integerpatternconverter.h>
#include <log4cxx/helpers/integer.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::pattern;
using namespace LOG4CXX_NS::helpers;

IMPLEMENT_LOG4CXX_OBJECT(IntegerPatternConverter)

IntegerPatternConverter::IntegerPatternConverter() :
	PatternConverter(LOG4CXX_STR("Integer"),
		LOG4CXX_STR("integer"))
{
}

PatternConverterPtr IntegerPatternConverter::newInstance(
	const std::vector<LogString>& /* options */)
{
	static WideLife<PatternConverterPtr> instance = std::make_shared<IntegerPatternConverter>();
	return instance;
}

void IntegerPatternConverter::format(
	const ObjectPtr& obj,
	LogString& toAppendTo,
	Pool& p) const
{
	IntegerPtr i = LOG4CXX_NS::cast<Integer>(obj);

	if (i != NULL)
	{
		StringHelper::toString(i->intValue(), p, toAppendTo);
	}
}
