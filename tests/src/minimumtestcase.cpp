/***************************************************************************
                             minimumtestcase.cpp
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
#include <log4cxx/simplelayout.h>
#include <log4cxx/ttcclayout.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/helpers/absolutetimedateformat.h>

#include "util/compare.h"
#include "util/transformer.h"
#include "util/linenumberfilter.h"
#include "util/controlfilter.h"
#include "util/absolutedateandtimefilter.h"
#include "util/threadfilter.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

#define FILTERED _T("output/filtered")

String TTCC_PAT =
	String(ABSOLUTE_DATE_AND_TIME_PAT)
	+ " \\[\\d*]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - Message \\d{1,2}";

String TTCC2_PAT =
	String(ABSOLUTE_DATE_AND_TIME_PAT)
	+ " \\[\\d*]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - Messages should bear numbers 0 through 23\\.";


class MinimumTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(MinimumTestCase);
		CPPUNIT_TEST(simple);
		CPPUNIT_TEST(ttcc);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp()
	{
		root = Logger::getRootLogger();
		root->removeAllAppenders();
	}

	void tearDown()
	{
		root->getLoggerRepository()->resetConfiguration();
	}

	void simple()
	{
		LayoutPtr layout = new SimpleLayout();
		AppenderPtr appender = new FileAppender(layout, _T("output/simple"), false);
		root->addAppender(appender);
		common();

		CPPUNIT_ASSERT(Compare::compare(_T("output/simple"), _T("witness/simple")));
	}

	void ttcc()
	{
		LayoutPtr layout =
			new TTCCLayout(AbsoluteTimeDateFormat::DATE_AND_TIME_DATE_FORMAT);
		AppenderPtr appender = new FileAppender(layout, "output/ttcc", false);
		root->addAppender(appender);
		common();

		ControlFilter filter1;
		filter1 << TTCC_PAT << TTCC2_PAT;
		AbsoluteDateAndTimeFilter filter2;
		ThreadFilter filter3;

		std::vector<Filter *> filters;
		filters.push_back(&filter1);
		filters.push_back(&filter2);
		filters.push_back(&filter3);

		try
		{
			Transformer::transform(_T("output/ttcc"), FILTERED, filters);
		}
		catch(UnexpectedFormatException& e)
		{
			tcout << "UnexpectedFormatException :" << e.getMessage() << std::endl;
			throw;
		}

		CPPUNIT_ASSERT(Compare::compare(FILTERED, _T("witness/ttcc")));
	}

	void common()
	{
		int i = 0;

		// In the lines below, the category names are chosen as an aid in
		// remembering their level values. In general, the category names
		// have no bearing to level values.
		LoggerPtr ERR = Logger::getLogger("ERR");
		ERR->setLevel(Level::getErrorLevel());

		LoggerPtr INF = Logger::getLogger("INF");
		INF->setLevel(Level::getInfoLevel());

		LoggerPtr INF_ERR = Logger::getLogger("INF.ERR");
		INF_ERR->setLevel(Level::getErrorLevel());

		LoggerPtr DEB = Logger::getLogger("DEB");
		DEB->setLevel(Level::getDebugLevel());

		// Note: categories with undefined level
		LoggerPtr INF_UNDEF = Logger::getLogger("INF.UNDEF");
		LoggerPtr INF_ERR_UNDEF = Logger::getLogger("INF.ERR.UNDEF");
		LoggerPtr UNDEF = Logger::getLogger("UNDEF");

		// These should all log.----------------------------
		LOG4CXX_FATAL(ERR, "Message " << i);
		i++; //0
		LOG4CXX_ERROR(ERR, "Message " << i);
		i++;

		LOG4CXX_FATAL(INF, "Message " << i);
		i++; // 2
		LOG4CXX_ERROR(INF, "Message " << i);
		i++;
		LOG4CXX_WARN(INF, "Message " << i);
		i++;
		LOG4CXX_INFO(INF, "Message " << i);
		i++;

		LOG4CXX_FATAL(INF_UNDEF, "Message " << i);
		i++; //6
		LOG4CXX_ERROR(INF_UNDEF, "Message " << i);
		i++;
		LOG4CXX_WARN(INF_UNDEF, "Message " << i);
		i++;
		LOG4CXX_INFO(INF_UNDEF, "Message " << i);
		i++;

		LOG4CXX_FATAL(INF_ERR, "Message " << i);
		i++; // 10
		LOG4CXX_ERROR(INF_ERR, "Message " << i);
		i++;

		LOG4CXX_FATAL(INF_ERR_UNDEF, "Message " << i);
		i++;
		LOG4CXX_ERROR(INF_ERR_UNDEF, "Message " << i);
		i++;

		LOG4CXX_FATAL(DEB, "Message " << i);
		i++; //14
		LOG4CXX_ERROR(DEB, "Message " << i);
		i++;
		LOG4CXX_WARN(DEB, "Message " << i);
		i++;
		LOG4CXX_INFO(DEB, "Message " << i);
		i++;
		LOG4CXX_DEBUG(DEB, "Message " << i);
		i++;

		// defaultLevel=DEBUG
		LOG4CXX_FATAL(UNDEF, "Message " << i);
		i++; // 19
		LOG4CXX_ERROR(UNDEF, "Message " << i);
		i++;
		LOG4CXX_WARN(UNDEF, "Message " << i);
		i++;
		LOG4CXX_INFO(UNDEF, "Message " << i);
		i++;
		LOG4CXX_DEBUG(UNDEF, "Message " << i);
		i++;

		// -------------------------------------------------
		// The following should not log
		LOG4CXX_WARN(ERR, "Message " << i);
		i++;
		LOG4CXX_INFO(ERR, "Message " << i);
		i++;
		LOG4CXX_DEBUG(ERR, "Message " << i);
		i++;

		LOG4CXX_DEBUG(INF, "Message " << i);
		i++;
		LOG4CXX_DEBUG(INF_UNDEF, "Message " << i);
		i++;

		LOG4CXX_WARN(INF_ERR, "Message " << i);
		i++;
		LOG4CXX_INFO(INF_ERR, "Message " << i);
		i++;
		LOG4CXX_DEBUG(INF_ERR, "Message " << i);
		i++;
		LOG4CXX_WARN(INF_ERR_UNDEF, "Message " << i);
		i++;
		LOG4CXX_INFO(INF_ERR_UNDEF, "Message " << i);
		i++;
		LOG4CXX_DEBUG(INF_ERR_UNDEF, "Message " << i);
		i++;

		// -------------------------------------------------
		LOG4CXX_INFO(INF, "Messages should bear numbers 0 through 23.");
	}

	LoggerPtr root;
	LoggerPtr logger;
};


CPPUNIT_TEST_SUITE_REGISTRATION(MinimumTestCase);
