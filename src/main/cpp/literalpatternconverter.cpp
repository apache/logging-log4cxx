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
#include <log4cxx/pattern/literalpatternconverter.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/spi/location/locationinfo.h>
#include <log4cxx/private/patternconverter_priv.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::pattern;
using namespace LOG4CXX_NS::spi;
using namespace LOG4CXX_NS::helpers;

#define priv static_cast<LiteralPatternConverterPrivate*>(m_priv.get())

struct LiteralPatternConverter::LiteralPatternConverterPrivate : public PatternConverterPrivate
{
	LiteralPatternConverterPrivate( const LogString& name, const LogString& style, const LogString& literal1 ) :
		PatternConverterPrivate( name, style ),
		literal(literal1) {}

	/**
	 * String literal.
	 */
	const LogString literal;
};

IMPLEMENT_LOG4CXX_OBJECT(LiteralPatternConverter)

LiteralPatternConverter::LiteralPatternConverter(const LogString& literal1) :
	LoggingEventPatternConverter(std::make_unique<LiteralPatternConverterPrivate>
		(LOG4CXX_STR("Literal"), LOG4CXX_STR("literal"), literal1))
{
}

PatternConverterPtr LiteralPatternConverter::newInstance(
	const LogString& literal)
{
	if (literal.length() == 1 && literal[0] == 0x20 /* ' ' */)
	{
		static WideLife<PatternConverterPtr> blank = std::make_shared<LiteralPatternConverter>(literal);
		return blank;
	}

	return std::make_shared<LiteralPatternConverter>(literal);
}

void LiteralPatternConverter::format(
	const LoggingEventPtr& /* event */,
	LogString& toAppendTo,
	Pool& /* p */) const
{
	toAppendTo.append(priv->literal);
}

void LiteralPatternConverter::format(
	const ObjectPtr& /* event */,
	LogString& toAppendTo,
	Pool& /* p */)  const
{
	toAppendTo.append(priv->literal);
}

