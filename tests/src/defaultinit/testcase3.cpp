/***************************************************************************
                             testcase3.cpp
                             -------------------
    begin                : 2004/01/05
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

#include <log4cxx/logmanager.h>
#include <log4cxx/logger.h>

using namespace log4cxx;

class TestCase3 : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(TestCase3);
		CPPUNIT_TEST(testProperties);
	CPPUNIT_TEST_SUITE_END();
	
public:
	void setUp()
	{
	}

	void tearDown()
	{
		LogManager::shutdown();
	}
	
	void testProperties()
	{
		LoggerPtr root = Logger::getRootLogger();
		bool rootIsConfigured = !root->getAllAppenders().empty();
		CPPUNIT_ASSERT(rootIsConfigured);
		
		AppenderList list = root->getAllAppenders();
		AppenderPtr appender = list.front();
		CPPUNIT_ASSERT_EQUAL(String(_T("D3")), appender->getName());
	}

};

CPPUNIT_TEST_SUITE_REGISTRATION(TestCase3);
