/***************************************************************************
                          asyncappendertestcase.cpp
                             -------------------
    begin                : 2003/12/16
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
#include <log4cxx/logmanager.h>
#include <log4cxx/simplelayout.h>
#include "vectorappender.h"
#include <log4cxx/asyncappender.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   A superficial but general test of log4j.
 */
class AsyncAppenderTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(AsyncAppenderTestCase);
		CPPUNIT_TEST(closeTest);
		CPPUNIT_TEST(test2);
		CPPUNIT_TEST(test3);
	CPPUNIT_TEST_SUITE_END();


public:
	void setUp() {}

	void tearDown()
	{
		LogManager::shutdown();
	}

	// this test checks whether it is possible to write to a closed AsyncAppender
	void closeTest() throw(Exception)
	{
		LoggerPtr root = Logger::getRootLogger();
		LayoutPtr layout = new SimpleLayout();
		VectorAppenderPtr vectorAppender = new VectorAppender();
		AsyncAppenderPtr asyncAppender = new AsyncAppender();
		asyncAppender->setName("async-CloseTest");
		asyncAppender->addAppender(vectorAppender);
		root->addAppender(asyncAppender);

		root->debug("m1");
		asyncAppender->close();
		root->debug("m2");

		const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
		CPPUNIT_ASSERT(v.size() == 1);
	}

	// this test checks whether appenders embedded within an AsyncAppender are also
	// closed
	void test2()
	{
		LoggerPtr root = Logger::getRootLogger();
		LayoutPtr layout = new SimpleLayout();
		VectorAppenderPtr vectorAppender = new VectorAppender();
		AsyncAppenderPtr asyncAppender = new AsyncAppender();
		asyncAppender->setName("async-test2");
		asyncAppender->addAppender(vectorAppender);
		root->addAppender(asyncAppender);

		root->debug("m1");
		asyncAppender->close();
		root->debug("m2");

		const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
		CPPUNIT_ASSERT(v.size() == 1);
		CPPUNIT_ASSERT(vectorAppender->isClosed());
	}

	// this test checks whether appenders embedded within an AsyncAppender are also
	// closed
	void test3()
	{
		int LEN = 200;
		LoggerPtr root = Logger::getRootLogger();
		LayoutPtr layout = new SimpleLayout();
		VectorAppenderPtr vectorAppender = new VectorAppender();
		AsyncAppenderPtr asyncAppender = new AsyncAppender();
		asyncAppender->setName("async-test3");
		asyncAppender->addAppender(vectorAppender);
		root->addAppender(asyncAppender);

		for (int i = 0; i < LEN; i++)
		{
			root->debug("message" + i);
		}

		asyncAppender->close();
		root->debug("m2");

		const std::vector<spi::LoggingEventPtr>& v = vectorAppender->getVector();
		CPPUNIT_ASSERT(v.size() == LEN);
		CPPUNIT_ASSERT(vectorAppender->isClosed());
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(AsyncAppenderTestCase);
