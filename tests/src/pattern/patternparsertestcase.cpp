/***************************************************************************
                             errorhandlertestcase.cpp
                             -------------------
    begin                : 2003/12/02
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/
 /***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the license.apl file.                                   *
 ***************************************************************************/

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/level.h>

#include "num343patternconverter.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

class PatternParserTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(PatternParserTestCase);
	CPPUNIT_TEST_SUITE_END();

	LoggerPtr logger;
	LoggingEventPtr event;
	long now;

public:
	void setUp()
	{
		logger = Logger::getLogger(_T("org.foobar"));
		now = System::currentTimeMillis() + 13;

		event = new LoggingEvent(
			Logger::getStaticClass().getName(), logger, Level::INFO, 
			_T("msg 1"));
	}

	void tearDown()
	{
		logger->getLoggerRepository()->resetConfiguration();
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(PatternParserTestCase);
