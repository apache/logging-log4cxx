/***************************************************************************
                             levelrangefiltertestcase.cpp
                             -------------------
    begin                : 2004/01/31
    copyright            : (C) 2004 by Michael CATANZARITI
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
#include <log4cxx/fileappender.h>
#include <log4cxx/level.h>
#include <log4cxx/varia/levelrangefilter.h>

#include "../util/compare.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::varia;

#define ACCEPT_FILE _T("output/LevelRangeFilter_accept")
#define ACCEPT_WITNESS _T("witness/LevelRangeFilter_accept")
#define NEUTRAL_FILE _T("output/LevelRangeFilter_neutral")
#define NEUTRAL_WITNESS _T("witness/LevelMatchFilter_neutral")

class LevelRangeFilterTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(LevelRangeFilterTestCase);
		CPPUNIT_TEST(accept);
		CPPUNIT_TEST(neutral);
	CPPUNIT_TEST_SUITE_END();

	LoggerPtr root;
	LoggerPtr logger;

public:
	void setUp()
	{
		root = Logger::getRootLogger();
		root->removeAllAppenders();
		logger = Logger::getLogger(_T("test"));
	}

	void tearDown()
	{
		root->getLoggerRepository()->resetConfiguration();
	}

	void accept()
	{
		// set up appender
		LayoutPtr layout = new SimpleLayout();
		AppenderPtr appender = new FileAppender(layout, ACCEPT_FILE, false);

		// create LevelMatchFilter
		LevelRangeFilterPtr rangeFilter = new LevelRangeFilter();

		// set it to accept on a match
		rangeFilter->setAcceptOnMatch(true);
			
		// attach match filter to appender
		appender->addFilter(rangeFilter);

		// set appender on root and set level to debug
		root->addAppender(appender);
		root->setLevel(Level::DEBUG);
		
		int passCount = 0;
		StringBuffer sbuf;

		// test with no min or max set
		sbuf << _T("pass ") << passCount << _T("; no min or max set");
		common(sbuf.str());
		passCount++;

		// test with a min set
		rangeFilter->setLevelMin(Level::WARN);
		sbuf.str(_T(""));
		sbuf << _T("pass ") << passCount << _T("; min set to WARN, max not set");
		common(sbuf.str());
		passCount++;

		// create a clean filter
		appender->clearFilters();
		rangeFilter = new LevelRangeFilter();
		appender->addFilter(rangeFilter);

		//test with max set
		rangeFilter->setLevelMax(Level::WARN);
		sbuf.str(_T(""));
		sbuf << _T("pass ") << passCount << _T("; min not set, max set to WARN");
		common(sbuf.str());
		passCount++;


		LevelPtr levelArray[] =
			{ Level::DEBUG, Level::INFO, Level::WARN, Level::ERROR, Level::FATAL };
			
		int length = sizeof(levelArray)/sizeof(levelArray[0]);

		for (int x = 0; x < length; x++)
		{
			// set the min level to match
			rangeFilter->setLevelMin(levelArray[x]);

			for (int y = length - 1; y >= 0; y--)
			{
				// set max level to match
				rangeFilter->setLevelMax(levelArray[y]);

				sbuf.str(_T(""));
				sbuf << _T("pass ") << passCount
					 << _T("; filter set to accept between ")
					 << levelArray[x]->toString()  << _T(" and ")
					 << levelArray[y]->toString() << _T(" msgs");
				common(sbuf.str());

				// increment passCount
				passCount++;
			}
		}
		
		CPPUNIT_ASSERT(Compare::compare(ACCEPT_FILE, ACCEPT_WITNESS));
	}
	
	void neutral()
	{
		// set up appender
		LayoutPtr layout = new SimpleLayout();
		AppenderPtr appender = new FileAppender(layout, ACCEPT_FILE, false);

		// create LevelMatchFilter
		LevelRangeFilterPtr rangeFilter = new LevelRangeFilter();

		// set it to accept on a match
		rangeFilter->setAcceptOnMatch(true);
			
		// attach match filter to appender
		appender->addFilter(rangeFilter);

		// set appender on root and set level to debug
		root->addAppender(appender);
		root->setLevel(Level::DEBUG);
		
		int passCount = 0;
		StringBuffer sbuf;

		// test with no min or max set
		sbuf << _T("pass ") << passCount << _T("; no min or max set");
		common(sbuf.str());
		passCount++;

		// test with a min set
		rangeFilter->setLevelMin(Level::WARN);
		sbuf.str(_T(""));
		sbuf << _T("pass ") << passCount << _T("; min set to WARN, max not set");
		common(sbuf.str());
		passCount++;

		// create a clean filter
		appender->clearFilters();
		rangeFilter = new LevelRangeFilter();
		appender->addFilter(rangeFilter);

		//test with max set
		rangeFilter->setLevelMax(Level::WARN);
		sbuf.str(_T(""));
		sbuf << _T("pass ") << passCount << _T("; min not set, max set to WARN");
		common(sbuf.str());
		passCount++;


		LevelPtr levelArray[] =
			{ Level::DEBUG, Level::INFO, Level::WARN, Level::ERROR, Level::FATAL };
			
		int length = sizeof(levelArray)/sizeof(levelArray[0]);

		for (int x = 0; x < length; x++)
		{
			// set the min level to match
			rangeFilter->setLevelMin(levelArray[x]);

			for (int y = length - 1; y >= 0; y--)
			{
				// set max level to match
				rangeFilter->setLevelMax(levelArray[y]);

				sbuf.str(_T(""));
				sbuf << _T("pass ") << passCount
					 << _T("; filter set to accept between ")
					 << levelArray[x]->toString()  << _T(" and ")
					 << levelArray[y]->toString() << _T(" msgs");
				common(sbuf.str());

				// increment passCount
				passCount++;
			}
		}
		
		CPPUNIT_ASSERT(Compare::compare(NEUTRAL_FILE, NEUTRAL_WITNESS));
 	}
	
	void common(const String& msg)
	{
		logger->debug(msg);
		logger->info(msg);
		logger->warn(msg);
		logger->error(msg);
		logger->fatal(msg);
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(LevelRangeFilterTestCase);
