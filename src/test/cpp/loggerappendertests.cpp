/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "logunit.h"
#include <log4cxx/logger.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;

class CountingAppender : public AppenderSkeleton
{
	public:
		int count;

		CountingAppender(int id) : count(0)
		{
			LogString name = LOG4CXX_STR("counter_");
			helpers::StringHelper::toString(id, name);
			setName(name);
		}

		void append( const spi::LoggingEventPtr& event ) override
		{
			count++;
		}

		void close() override
		{}

		bool requiresLayout() const override
		{
			return false;
		}
};
using CountingAppenderPtr = std::shared_ptr<CountingAppender>;

LOGUNIT_CLASS(LoggerAppenderCacheConsistencyTest)
{
	LOGUNIT_TEST_SUITE(LoggerAppenderCacheConsistencyTest);

	// Basic hierarchy tests
	LOGUNIT_TEST(testRootLoggerInitialState);
	LOGUNIT_TEST(testSingleLoggerReplaceAppender);
	LOGUNIT_TEST(testSingleLoggerAddsToRoot);

	// Simple parent-child tests
	LOGUNIT_TEST(testTwoLevelHierarchyChildInherits);
	LOGUNIT_TEST(testTwoLevelHierarchyChildRemovesAdditivity);
	LOGUNIT_TEST(testTwoLevelHierarchyParentChanges);

	// Multi-level hierarchy tests
	LOGUNIT_TEST(testThreeLevelHierarchyAllInherit);
	LOGUNIT_TEST(testThreeLevelHierarchyMiddleRemovesAdditivity);
	LOGUNIT_TEST(testThreeLevelHierarchyLeafRemovesAdditivity);
	LOGUNIT_TEST(testFourLevelHierarchyMiddleRemovesAdditivity);

	// Dynamic parent change tests
	LOGUNIT_TEST(testSetParentFromNullToValid);
	LOGUNIT_TEST(testSetParentChangeParent);
	LOGUNIT_TEST(testSetParentMultipleTimes);

	// Appender change propagation tests
	LOGUNIT_TEST(testRootAppenderChangePropagatesToChildren);

	LOGUNIT_TEST_SUITE_END();

private:
	HierarchyPtr hierarchy;
	LoggerPtr rootLogger;
	CountingAppenderPtr appender1;
	CountingAppenderPtr appender2;
	CountingAppenderPtr appender3;

public:
	void setUp() override
	{
		appender1 = std::make_shared<CountingAppender>(1);
		hierarchy = Hierarchy::create();
		rootLogger = hierarchy->getRootLogger();
		rootLogger->addAppender(appender1);
		appender2 = std::make_shared<CountingAppender>(2);
		appender3 = std::make_shared<CountingAppender>(3);
	}

	void tearDown() override
	{
		hierarchy->resetConfiguration();
		hierarchy.reset();
		appender1.reset();
		appender2.reset();
	}

public:
	// Test 1: Root logger initial state
	void testRootLoggerInitialState()
	{
		rootLogger->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
	}

	// Test 2: Single logger replace appender
	void testSingleLoggerReplaceAppender()
	{
		auto logger = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		logger->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);

		rootLogger->replaceAppender(appender1, appender2);
		logger->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
	}

	// Test 3: Single logger adds to root
	void testSingleLoggerAddsToRoot()
	{
		LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		logger->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);

		logger->addAppender(appender2);
		logger->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);

		logger->removeAppender(appender2);
		logger->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
	}

	// Test 4: Two-level hierarchy - child adds to root
	void testTwoLevelHierarchyChildInherits()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);

		child->addAppender(appender2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);

		child->removeAllAppenders();
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
	}

	// Test 5: Two-level hierarchy - child removes additivity
	void testTwoLevelHierarchyChildRemovesAdditivity()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);

		child->addAppender(appender2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		child->setAdditivity(false);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);
	}

	// Test 6: Two-level hierarchy - parent change after child removes additivity
	void testTwoLevelHierarchyParentChanges()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);

		child->addAppender(appender2);
		child->setAdditivity(false);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		// Change parent - child should maintain its additivity
		rootLogger->replaceAppender(appender1, appender3);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 0);
	}

	// Test 7: Three-level hierarchy - all inherit
	void testThreeLevelHierarchyAllInherit()
	{
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));

		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		// Change parent - additivity should persist
		rootLogger->replaceAppender(appender1, appender2);
		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
	}

	// Test 8: Three-level hierarchy - middle removes additivity
	void testThreeLevelHierarchyMiddleRemovesAdditivity()
	{
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));

		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);

		level2->addAppender(appender2);
		level2->setAdditivity(false);
		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);
	}

	// Test 9: Three-level hierarchy - leaf removes additivity
	void testThreeLevelHierarchyLeafRemovesAdditivity()
	{
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));

		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);

		level3->addAppender(appender2);
		level3->setAdditivity(false);
		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 5);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 5);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
	}

	// Test 10: Four-level hierarchy - mixed additivity
	void testFourLevelHierarchyMiddleRemovesAdditivity()
	{
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("org"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("org.apache"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("org.apache.log4cxx"));
		LoggerPtr level4 = hierarchy->getLogger(LOG4CXX_STR("org.apache.log4cxx.test"));

		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		level4->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);

		level1->addAppender(appender2);
		level1->setAdditivity(false);
		level4->addAppender(appender3);
		level4->setAdditivity(false);
		level1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 0);
		level2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 0);
		level3->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 0);
		level4->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 1);
	}

	// Test 11: Set parent from null to valid
	void testSetParentFromNullToValid()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));
		parent->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);

		child->addAppender(appender2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);

		child->changeParentTo(parent);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);
	}

	// Test 12: Change parent
	void testSetParentChangeParent()
	{
		LoggerPtr parent1 = hierarchy->getLogger(LOG4CXX_STR("parent1"));
		LoggerPtr parent2 = hierarchy->getLogger(LOG4CXX_STR("parent2"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));
		parent1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		parent2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);

		child->addAppender(appender2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);

		child->changeParentTo(parent1);
		parent1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 5);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		parent2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 6);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 7);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);

		child->changeParentTo(parent2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 8);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
	}

	// Test 13: Set parent multiple times
	void testSetParentMultipleTimes()
	{
		LoggerPtr parent1 = hierarchy->getLogger(LOG4CXX_STR("p1"));
		LoggerPtr parent2 = hierarchy->getLogger(LOG4CXX_STR("p2"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));

		parent1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		parent2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);

		child->changeParentTo(parent1);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 4);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);

		child->changeParentTo(parent1);
		parent1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 5);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);
		parent2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 6);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 7);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);

		child->changeParentTo(parent2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 8);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 0);

		child->addAppender(appender2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 9);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);

		child->changeParentTo(parent1);
		parent1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 10);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		parent2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 11);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 12);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);

		child->changeParentTo(parent2);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 13);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);

		child->changeParentTo(rootLogger);
		parent1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 14);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
		parent2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 15);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
		child->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 16);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 4);
	}

	// Test 14: Root level change propagates to children
	void testRootAppenderChangePropagatesToChildren()
	{
		LoggerPtr child1 = hierarchy->getLogger(LOG4CXX_STR("child1"));
		LoggerPtr child2 = hierarchy->getLogger(LOG4CXX_STR("child2"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("child1.grandchild"));

		child1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 1);
		child2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 2);
		grandchild->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);

		rootLogger->replaceAppender(appender1, appender2);
		child1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 1);
		child2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 2);
		grandchild->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);

		rootLogger->replaceAppender(appender2, appender3);
		child1->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 1);
		child2->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 2);
		grandchild->addInfoEvent("message");
		LOGUNIT_ASSERT_EQUAL(appender1->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender2->count, 3);
		LOGUNIT_ASSERT_EQUAL(appender3->count, 3);
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(LoggerAppenderCacheConsistencyTest);
