/***************************************************************************
						   customleveltestcase.cpp
                             -------------------
    begin                : 2004/01/20
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
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/patternlayout.h>

#include "../util/compare.h"
#include "xlevel.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

#define TEMP _T("output/temp")

class CustomLevelTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(CustomLevelTestCase);
		CPPUNIT_TEST(test1);
		CPPUNIT_TEST(test2);
		CPPUNIT_TEST(test3);
		CPPUNIT_TEST(test4);
	CPPUNIT_TEST_SUITE_END();

	LoggerPtr root;
	LoggerPtr logger;

public:
	void setUp()
	{
		root = Logger::getRootLogger();
		logger = Logger::getLogger(_T("xml.CustomLevelTestCase"));
	}

	void tearDown()
	{
		root->getLoggerRepository()->resetConfiguration();

		LoggerPtr logger = Logger::getLogger(_T("LOG4J"));
		logger->setAdditivity(false);
		logger->addAppender(
			new ConsoleAppender(new PatternLayout(_T("log4j: %-22c{2} - %m%n"))));
	}

	void test1()
	{
		DOMConfigurator::configure(_T("input/xml/customLevel1.xml"));
		common();
		CPPUNIT_ASSERT(Compare::compare(TEMP, _T("witness/customLevel.1")));
	}

	void test2()
	{
		DOMConfigurator::configure(_T("input/xml/customLevel2.xml"));
		common();
		CPPUNIT_ASSERT(Compare::compare(TEMP, _T("witness/customLevel.2")));
	}

	void test3()
	{
		DOMConfigurator::configure(_T("input/xml/customLevel3.xml"));
		common();
		CPPUNIT_ASSERT(Compare::compare(TEMP, _T("witness/customLevel.3")));
	}

	void test4()
	{
		DOMConfigurator::configure(_T("input/xml/customLevel4.xml"));
		common();
		CPPUNIT_ASSERT(Compare::compare(TEMP, _T("witness/customLevel.4")));
	}

	void common()
	{
		int i = 0;
		LOG4CXX_DEBUG(logger, _T("Message ") << ++i);
		LOG4CXX_INFO(logger, _T("Message ") << ++i);
		LOG4CXX_WARN(logger, _T("Message ") << ++i);
		LOG4CXX_ERROR(logger, _T("Message ") << ++i);
		LOG4CXX_LOG(logger, XLevel::TRACE, _T("Message ") << ++i);
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(CustomLevelTestCase);
