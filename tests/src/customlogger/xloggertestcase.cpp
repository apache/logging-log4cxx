/***************************************************************************
                             xloggertestcase.cpp
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
#include "xlogger.h"
#include <log4cxx/xml/domconfigurator.h>
#include "../util/transformer.h"
#include "../util/compare.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

#define FILTERED "output/filtered"


/**
   Tests handling of custom loggers.
*/
class XLoggerTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(XLoggerTestCase);
		CPPUNIT_TEST(test1);
		CPPUNIT_TEST(test2);
	CPPUNIT_TEST_SUITE_END();

	XLoggerPtr logger;

public:
	void setUp()
	{
		logger =
			(XLoggerPtr) XLogger::getLogger(
			"org.apache.log4j.customLogger.XLoggerTestCase");
	}

	void tearDown()
	{
		logger->getLoggerRepository()->resetConfiguration();
	}

	void test1() { common("1"); }
	void test2() { common("2"); }

	void common(const String& number)
	{
		DOMConfigurator::configure("input/xml/customLogger"+number+".xml");

		int i = -1;
		LOG4CXX_TRACE(logger, "Message " << ++i);
		LOG4CXX_DEBUG(logger, "Message " << ++i);
		LOG4CXX_WARN(logger, "Message " << ++i);
		LOG4CXX_ERROR(logger, "Message " << ++i);
		LOG4CXX_FATAL(logger, "Message " << ++i);
		LOG4CXX_DEBUG(logger, "Message " << ++i);

/*		Transformer::transform("output/temp", FILTERED, new Filter[] {
													new LineNumberFilter(),
													new SunReflectFilter()});
		CPPUNIT_ASSERT(Compare::compare(FILTERED, "witness/customLogger."+number));
*/
		CPPUNIT_ASSERT(Compare::compare("output/temp", "witness/customLogger."+number));
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(XLoggerTestCase);
