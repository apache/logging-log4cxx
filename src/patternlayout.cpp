/***************************************************************************
                          patternlayout.cpp  -  class PatternLayout
                             -------------------
    begin                : dim avr 20 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/patternlayout.h>
#include <log4cxx/helpers/patternparser.h>
#include <log4cxx/helpers/patternconverter.h>
#include <log4cxx/helpers/stringhelper.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(PatternLayout)

/** Default pattern string for log output. Currently set to the
string <b>"%m%n"</b> which just prints the application supplied
message. */
String PatternLayout::DEFAULT_CONVERSION_PATTERN = _T("%m%n");

/** A conversion pattern equivalent to the TTCCCLayout.
Current value is <b>%r [%t] %p %c %x - %m%n</b>. */
String PatternLayout::TTCC_CONVERSION_PATTERN = _T("%r [%t] %p %c %x - %m%n");

int PatternLayout::BUF_SIZE = 256;
int PatternLayout::MAX_CAPACITY = 1024;

PatternLayout::PatternLayout()
{
}

/**
Constructs a PatternLayout using the supplied conversion pattern.
*/
PatternLayout::PatternLayout(const String& pattern) : pattern(pattern)
{
	activateOptions();
}

void PatternLayout::setConversionPattern(const String& conversionPattern)
{
	pattern = conversionPattern;
	activateOptions();
}

void PatternLayout::format(ostream& output, const spi::LoggingEvent& event)
{
	PatternConverterPtr c = head;
	
	while(c != 0)
	{
		c->format(output, event);
		c = c->next;
	}
}

PatternConverterPtr PatternLayout::createPatternParser(const String& pattern)
{
	return PatternParser(pattern, timeZone).parse();
}

void PatternLayout::setOption(const String& option, const String& value)
{
	if (StringHelper::equalsIgnoreCase(option, _T("conversionpattern")))
	{
		pattern = value;
	}
}

void PatternLayout::activateOptions()
{
	if (pattern.empty())
	{
		pattern = DEFAULT_CONVERSION_PATTERN;
	}

	head = createPatternParser(pattern);
}






