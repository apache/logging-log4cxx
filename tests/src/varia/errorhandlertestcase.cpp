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
#include <log4cxx/xml/domconfigurator.h>

#include "../util/transformer.h"
#include "../util/compare.h"
#include "../util/controlfilter.h"
#include "../util/threadfilter.h"
#include "../util/linenumberfilter.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

#define TEMP _T("output/temp")
#define FILTERED _T("output/filtered")
#define TEST1_A_PAT _T("FALLBACK - test - Message \\d")
#define TEST1_B_PAT _T("FALLBACK - root - Message \\d")
#define TEST1_2_PAT \
	_T("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3} ") \
	_T("\\[main]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - Message \\d")

class ErrorHandlerTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(ErrorHandlerTestCase);
		CPPUNIT_TEST(test1);
	CPPUNIT_TEST_SUITE_END();

	LoggerPtr root;
	LoggerPtr logger;

public:
	void setUp()
	{
		root = Logger::getRootLogger();
		logger = Logger::getLogger(_T("test"));
	}

	void tearDown()
	{
		logger->getLoggerRepository()->resetConfiguration();
	}

	void test1()
	{
   		DOMConfigurator::configure(_T("input/xml/fallback1.xml"));
		common();
		
		ControlFilter cf;
		cf << TEST1_A_PAT << TEST1_B_PAT << TEST1_2_PAT;
		
		ThreadFilter threadFilter;
		LineNumberFilter lineNumberFilter;

		std::vector<Filter *> filters;
		filters.push_back(&cf);
		filters.push_back(&threadFilter);
		filters.push_back(&lineNumberFilter);

		try
		{
			Transformer::transform(TEMP, FILTERED, filters);
		}
		catch(UnexpectedFormatException& e)
		{
			tcout << _T("UnexpectedFormatException :") << e.getMessage() << std::endl;
			throw;
		}

		CPPUNIT_ASSERT(Compare::compare(FILTERED, _T("witness/fallback")));
	}
	
	void common()
	{
		int i = -1;

		LOG4CXX_DEBUG(logger, _T("Message ") << ++i);
		LOG4CXX_DEBUG(root, _T("Message ") << i);

		LOG4CXX_INFO(logger, _T("Message ") << ++i);
		LOG4CXX_INFO(root, _T("Message ") << i);

		LOG4CXX_WARN(logger, _T("Message ") << ++i);
		LOG4CXX_WARN(root, _T("Message ") << i);

		LOG4CXX_ERROR(logger, _T("Message ") << ++i);
		LOG4CXX_ERROR(root, _T("Message ") << i);

		LOG4CXX_FATAL(logger, _T("Message ") << ++i);
		LOG4CXX_FATAL(root, _T("Message ") << i);
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(ErrorHandlerTestCase);
