/***************************************************************************
                             l7dtestcase.cpp
                             -------------------
    begin                : 2003/12/31
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
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/helpers/propertyresourcebundle.h>

#include "util/compare.h"

#include <vector>


using namespace log4cxx;
using namespace log4cxx::helpers;

class L7dTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(L7dTestCase);
		CPPUNIT_TEST(test1);
	CPPUNIT_TEST_SUITE_END();
	
	LoggerPtr root;
	ResourceBundlePtr bundles[3];
	
public:
	void setUp()
	{
		bundles[0] = 
			ResourceBundle::getBundle(_T("L7D"), Locale(_T("en"), _T("US")));
		CPPUNIT_ASSERT(bundles[0] != 0);

		bundles[1] =
			ResourceBundle::getBundle(_T("L7D"), Locale(_T("fr"), _T("FR")));
		CPPUNIT_ASSERT(bundles[1] != 0);

		bundles[2] = 
			ResourceBundle::getBundle(_T("L7D"), Locale(_T("fr"), _T("CH")));
		CPPUNIT_ASSERT(bundles[2] != 0);
		
		root = Logger::getRootLogger();
	}

	void tearDown()
	{
		root->getLoggerRepository()->resetConfiguration();
	}
	
	void test1()
	{
		PropertyConfigurator::configure(_T("input/l7d1.properties"));
		
		for (int i = 0; i < 3; i++)
		{
			root->setResourceBundle(bundles[i]);

			LOG4CXX_L7DLOG(root, Level::DEBUG, _T("bogus1"));            
			LOG4CXX_L7DLOG(root, Level::INFO, _T("test"));
			LOG4CXX_L7DLOG(root, Level::WARN, _T("hello_world"));
			
			StringBuffer sbuf;
			sbuf << (i+1);
			LOG4CXX_L7DLOG2(root, Level::DEBUG, _T("msg1"), sbuf.str().c_str(),
				 _T("log4j"));
			LOG4CXX_L7DLOG2(root, Level::ERROR, _T("bogusMsg"), sbuf.str().c_str(),
				 _T("log4j"));
			LOG4CXX_L7DLOG2(root, Level::ERROR, _T("msg1"), sbuf.str().c_str(),
				 _T("log4j"));
			LOG4CXX_L7DLOG(root, Level::INFO, _T("bogus2"));
		}

		CPPUNIT_ASSERT(Compare::compare(_T("output/temp"), _T("witness/l7d.1")));
	}
	
};

CPPUNIT_TEST_SUITE_REGISTRATION(L7dTestCase);
