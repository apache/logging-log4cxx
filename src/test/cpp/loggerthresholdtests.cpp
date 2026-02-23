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

#include <log4cxx/logger.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/level.h>
#include "logunit.h"
#if LOG4CXX_ABI_VERSION <= 15
#include <log4cxx/defaultloggerfactory.h>
#else
#include <log4cxx/spi/loggerfactory.h>
#endif
#include <log4cxx/helpers/transcoder.h>

/****
This comprehensive test suite verifies that Logger::m_threshold always equals Logger::getEffectiveLevel()->toInt().

Basic Scenarios (Tests 1-6)
•	Root logger initialization
•	Single logger level setting
•	Simple inheritance
•	Two-level hierarchies with inheritance and overrides

Multi-Level Hierarchies (Tests 7-10)
•	Three and four-level hierarchies
•	Various override patterns (middle, leaf, mixed)

Dynamic Parent Changes (Tests 11-13)
•	Setting parent from null
•	Changing parents
•	Multiple parent reassignments

Level Propagation (Tests 14-16)
•	Root level changes propagating to children
•	Parent changes propagating to grandchildren
•	Verification that overridden children don't change

Complex Hierarchies (Tests 17-19)
•	Mixed level configurations
•	Sibling independence
•	Deep hierarchies (7+ levels)

Null Level Handling (Tests 20-22)
•	Setting level to null and inheritance
•	Toggling between null and values
•	Null levels with parent changes

Edge Cases (Tests 23-25)
•	All standard levels (OFF, FATAL, ERROR, WARN, INFO, DEBUG, TRACE, ALL)
•	Rapid level changes
•	Interleaved parent and child changes

Creation Order (Tests 26-28)
•	Child created before parent
•	Provision node scenarios
•	Out-of-order creation

Advanced Scenarios (Tests 29-50)
•	Multiple children before parent
•	Complex interleaved creation
•	Wide hierarchies (many siblings)
•	Deep hierarchies with alternating overrides
•	Same parent reassignment
•	Root affecting entire hierarchy
•	Mixed null and non-null levels
•	Multiple parent changes with verification
•	Grandchildren before ancestors
•	Stress tests with many changes
•	Different name patterns
•	All-null chains except root

Concurrent Branches (Tests 41-50)
•	Multiple independent branches
•	Cross-branch changes
•	Extremely deep hierarchies (50 levels)
•	Logger retrieval consistency
•	Factory-created loggers

Special Patterns (Tests 51-65)
•	Parent-child swaps
•	All same level
•	Rapid reassignments
•	Zigzag patterns
•	Level removal and re-addition
•	Diamond hierarchies
•	Very long names
•	Same level multiple times
•	Complex mixed operations
•	Empty and single-character names
•	Final comprehensive stress test

***/

using namespace log4cxx;

LOGUNIT_CLASS(LoggerThresholdConsistencyTest)
{
	LOGUNIT_TEST_SUITE(LoggerThresholdConsistencyTest);

	// Basic hierarchy tests
	LOGUNIT_TEST(testRootLoggerInitialState);
	LOGUNIT_TEST(testSingleLoggerSetLevel);
	LOGUNIT_TEST(testSingleLoggerInheritsFromRoot);

	// Simple parent-child tests
	LOGUNIT_TEST(testTwoLevelHierarchyChildInherits);
	LOGUNIT_TEST(testTwoLevelHierarchyChildOverrides);
	LOGUNIT_TEST(testTwoLevelHierarchyParentChanges);

	// Multi-level hierarchy tests
	LOGUNIT_TEST(testThreeLevelHierarchyAllInherit);
	LOGUNIT_TEST(testThreeLevelHierarchyMiddleOverrides);
	LOGUNIT_TEST(testThreeLevelHierarchyLeafOverrides);
	LOGUNIT_TEST(testFourLevelHierarchyMixedOverrides);

	// Dynamic parent change tests
	LOGUNIT_TEST(testSetParentFromNullToValid);
	LOGUNIT_TEST(testSetParentChangeParent);
	LOGUNIT_TEST(testSetParentMultipleTimes);

	// Level change propagation tests
	LOGUNIT_TEST(testRootLevelChangePropagatesToChildren);
	LOGUNIT_TEST(testParentLevelChangePropagatesToGrandchildren);
	LOGUNIT_TEST(testLevelChangeDoesNotPropagateToOverriddenChildren);

	// Complex hierarchy tests
	LOGUNIT_TEST(testComplexHierarchyWithMixedLevels);
	LOGUNIT_TEST(testSiblingLoggersIndependent);
	LOGUNIT_TEST(testDeepHierarchyInheritance);

	// Level set to null tests
	LOGUNIT_TEST(testSetLevelToNullInheritsFromParent);
	LOGUNIT_TEST(testSetLevelToNullThenBackToValue);
	LOGUNIT_TEST(testChildSetToNullAfterParentChange);

	// Edge cases
	LOGUNIT_TEST(testAllStandardLevels);
	LOGUNIT_TEST(testRapidLevelChanges);
	LOGUNIT_TEST(testParentAndChildLevelChangesInterleaved);

	// Hierarchy reorganization tests
	LOGUNIT_TEST(testLoggerCreationOrderDoesNotMatter);
	LOGUNIT_TEST(testChildCreatedBeforeParent);
	LOGUNIT_TEST(testProvisionNodeScenario);

	// Additional miscellaneous tests
	LOGUNIT_TEST(testMultipleChildrenBeforeParent);
	LOGUNIT_TEST(testComplexInterleavedCreationAndLevelSetting);
	LOGUNIT_TEST(testWideHierarchy);
	LOGUNIT_TEST(testDeepHierarchyAlternatingOverrides);
	LOGUNIT_TEST(testSetParentToSameParent);
	LOGUNIT_TEST(testRootLoggerAffectsEntireHierarchy);
	LOGUNIT_TEST(testMixedNullAndNonNullLevels);
	LOGUNIT_TEST(testThresholdAfterMultipleParentChanges);
	LOGUNIT_TEST(testGrandchildBeforeParentAndMiddle);
	LOGUNIT_TEST(testStressTestManyLevelChanges);
	LOGUNIT_TEST(testDifferentNamePatterns);
	LOGUNIT_TEST(testParentChainAllNullExceptRoot);
	LOGUNIT_TEST(testConcurrentHierarchyBranches);
	LOGUNIT_TEST(testSetLevelOnLoggerWithExistingChildren);
	LOGUNIT_TEST(testAlternatingSetLevelAndSetParent);
	LOGUNIT_TEST(testOffAndAllLevels);
	LOGUNIT_TEST(testComplexProvisionNodeScenario);
	LOGUNIT_TEST(testMultipleSiblingsWithDifferentLevels);
	LOGUNIT_TEST(testParentChainWithGaps);
	LOGUNIT_TEST(testThresholdAfterHierarchyOperations);
	LOGUNIT_TEST(testCrossBranchHierarchyChanges);
	LOGUNIT_TEST(testExtremelyDeepHierarchy);
	LOGUNIT_TEST(testThresholdConsistencyDuringRetrieval);
	LOGUNIT_TEST(testThresholdConsistencyWithLoggerFactory);
	LOGUNIT_TEST(testThresholdAfterParentChildSwap);
	LOGUNIT_TEST(testThresholdWithAllSameLevel);
	LOGUNIT_TEST(testThresholdAfterRapidParentReassignments);
	LOGUNIT_TEST(testThresholdWithZigzagLevelPattern);
	LOGUNIT_TEST(testThresholdAfterRemovingAndReaddingLevels);
	LOGUNIT_TEST(testThresholdWithDiamondHierarchy);
	LOGUNIT_TEST(testThresholdWithVeryLongLoggerNames);
	LOGUNIT_TEST(testThresholdAfterSettingSameLevelMultipleTimes);
	LOGUNIT_TEST(testComplexMixedOperations);
	LOGUNIT_TEST(testThresholdAfterParentChangeWithGrandchildren);
	LOGUNIT_TEST(testThresholdWithEmptyLoggerName);
	LOGUNIT_TEST(testThresholdWithSingleCharacterNames);
	LOGUNIT_TEST(testFinalComprehensiveStressTest);

	LOGUNIT_TEST_SUITE_END();

private:
	HierarchyPtr hierarchy;

public:
	void setUp() override
	{
		hierarchy = Hierarchy::create();
	}

	void tearDown() override
	{
		hierarchy->resetConfiguration();
		hierarchy.reset();
	}

	void assertThresholdConsistent(const LoggerPtr& logger)
	{
		LOG4CXX_ENCODE_CHAR(name, logger->getName());
		LOGUNIT_ASSERT_MESSAGE(logger->isThresholdValid()
			, "threshold does not match getEffectiveLevel()->toInt() for logger: " + name);
	}

	void assertThresholdIs(const LevelPtr& level, const LoggerPtr& logger)
	{
		LOG4CXX_ENCODE_CHAR(levelName, level->toString());
		LOG4CXX_ENCODE_CHAR(loggerName, logger->getName());
		LOGUNIT_ASSERT_MESSAGE(logger->isThresholdEqualTo(level)
			, "threshold is not " + levelName + " for logger: " + loggerName);
	}

	void assertThresholdIs(const LoggerPtr& other, const LoggerPtr& logger)
	{
		LOG4CXX_ENCODE_CHAR(name1, other->getName());
		LOG4CXX_ENCODE_CHAR(name2, logger->getName());
		LOGUNIT_ASSERT_MESSAGE(logger->isThresholdEqualTo(other)
			, "threshold is not the same as " + name1 + " for logger: " + name2);
	}

public:
	// Test 1: Root logger initial state
	void testRootLoggerInitialState()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		assertThresholdConsistent(root);
	}

	// Test 2: Single logger set level
	void testSingleLoggerSetLevel()
	{
		LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		assertThresholdConsistent(logger);

		logger->setLevel(Level::getInfo());
		assertThresholdConsistent(logger);

		logger->setLevel(Level::getDebug());
		assertThresholdConsistent(logger);

		logger->setLevel(Level::getError());
		assertThresholdConsistent(logger);
	}

	// Test 3: Single logger inherits from root
	void testSingleLoggerInheritsFromRoot()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("com.example"));

		root->setLevel(Level::getWarn());
		assertThresholdConsistent(logger);

		root->setLevel(Level::getTrace());
		assertThresholdConsistent(logger);
	}

	// Test 4: Two-level hierarchy - child inherits
	void testTwoLevelHierarchyChildInherits()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("com.example"));

		parent->setLevel(Level::getInfo());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);

		parent->setLevel(Level::getError());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
	}

	// Test 5: Two-level hierarchy - child overrides
	void testTwoLevelHierarchyChildOverrides()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("com.example"));

		parent->setLevel(Level::getWarn());
		child->setLevel(Level::getDebug());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);

		assertThresholdIs(Level::getWarn(), parent);
		assertThresholdIs(Level::getDebug(), child);
	}

	// Test 6: Two-level hierarchy - parent changes after child override
	void testTwoLevelHierarchyParentChanges()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("com.example"));

		parent->setLevel(Level::getWarn());
		child->setLevel(Level::getDebug());

		// Change parent - child should maintain its override
		parent->setLevel(Level::getError());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);

		assertThresholdIs(Level::getDebug(), child);
	}

	// Test 7: Three-level hierarchy - all inherit
	void testThreeLevelHierarchyAllInherit()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));

		root->setLevel(Level::getInfo());
		assertThresholdConsistent(root);
		assertThresholdConsistent(level1);
		assertThresholdConsistent(level2);
		assertThresholdConsistent(level3);
	}

	// Test 8: Three-level hierarchy - middle overrides
	void testThreeLevelHierarchyMiddleOverrides()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));

		root->setLevel(Level::getError());
		level2->setLevel(Level::getDebug());

		assertThresholdConsistent(root);
		assertThresholdConsistent(level1);
		assertThresholdConsistent(level2);
		assertThresholdConsistent(level3);

		assertThresholdIs(Level::getError(), level1);
		assertThresholdIs(Level::getDebug(), level2);
		assertThresholdIs(Level::getDebug(), level3);
	}

	// Test 9: Three-level hierarchy - leaf overrides
	void testThreeLevelHierarchyLeafOverrides()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));

		root->setLevel(Level::getWarn());
		level3->setLevel(Level::getTrace());

		assertThresholdConsistent(root);
		assertThresholdConsistent(level1);
		assertThresholdConsistent(level2);
		assertThresholdConsistent(level3);

		assertThresholdIs(Level::getWarn(), level1);
		assertThresholdIs(Level::getWarn(), level2);
		assertThresholdIs(Level::getTrace(), level3);
	}

	// Test 10: Four-level hierarchy - mixed overrides
	void testFourLevelHierarchyMixedOverrides()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr level1 = hierarchy->getLogger(LOG4CXX_STR("org"));
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("org.apache"));
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("org.apache.log4cxx"));
		LoggerPtr level4 = hierarchy->getLogger(LOG4CXX_STR("org.apache.log4cxx.test"));

		root->setLevel(Level::getError());
		level2->setLevel(Level::getInfo());
		level4->setLevel(Level::getDebug());

		assertThresholdConsistent(root);
		assertThresholdConsistent(level1);
		assertThresholdConsistent(level2);
		assertThresholdConsistent(level3);
		assertThresholdConsistent(level4);

		assertThresholdIs(Level::getError(), level1);
		assertThresholdIs(Level::getInfo(), level2);
		assertThresholdIs(Level::getInfo(), level3);
		assertThresholdIs(Level::getDebug(), level4);
	}

	// Test 11: Set parent from null to valid
	void testSetParentFromNullToValid()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));

		parent->setLevel(Level::getWarn());
		child->changeParentTo(parent);

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
	}

	// Test 12: Change parent
	void testSetParentChangeParent()
	{
		LoggerPtr parent1 = hierarchy->getLogger(LOG4CXX_STR("parent1"));
		LoggerPtr parent2 = hierarchy->getLogger(LOG4CXX_STR("parent2"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));

		parent1->setLevel(Level::getDebug());
		parent2->setLevel(Level::getError());

		child->changeParentTo(parent1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getDebug(), child);

		child->changeParentTo(parent2);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getError(), child);
	}

	// Test 13: Set parent multiple times
	void testSetParentMultipleTimes()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr parent1 = hierarchy->getLogger(LOG4CXX_STR("p1"));
		LoggerPtr parent2 = hierarchy->getLogger(LOG4CXX_STR("p2"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));

		root->setLevel(Level::getFatal());
		parent1->setLevel(Level::getInfo());
		parent2->setLevel(Level::getDebug());

		child->changeParentTo(root);
		assertThresholdConsistent(child);

		child->changeParentTo(parent1);
		assertThresholdConsistent(child);

		child->changeParentTo(parent2);
		assertThresholdConsistent(child);

		child->changeParentTo(root);
		assertThresholdConsistent(child);
	}

	// Test 14: Root level change propagates to children
	void testRootLevelChangePropagatesToChildren()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr child1 = hierarchy->getLogger(LOG4CXX_STR("child1"));
		LoggerPtr child2 = hierarchy->getLogger(LOG4CXX_STR("child2"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("child1.grandchild"));

		root->setLevel(Level::getWarn());
		assertThresholdConsistent(child1);
		assertThresholdConsistent(child2);
		assertThresholdConsistent(grandchild);

		root->setLevel(Level::getDebug());
		assertThresholdConsistent(child1);
		assertThresholdConsistent(child2);
		assertThresholdConsistent(grandchild);
	}

	// Test 15: Parent level change propagates to grandchildren
	void testParentLevelChangePropagatesToGrandchildren()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("parent.child.grandchild"));

		root->setLevel(Level::getError());
		parent->setLevel(Level::getInfo());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		parent->setLevel(Level::getDebug());
		assertThresholdIs(Level::getDebug(), grandchild);
	}

	// Test 16: Level change does not propagate to overridden children
	void testLevelChangeDoesNotPropagateToOverriddenChildren()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("parent.child.grandchild"));

		root->setLevel(Level::getError());
		parent->setLevel(Level::getInfo());
		child->setLevel(Level::getDebug());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		// Change parent level
		parent->setLevel(Level::getWarn());

		// Child should keep its own level
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		assertThresholdIs(Level::getWarn(), parent);
		assertThresholdIs(Level::getDebug(), child);
		assertThresholdIs(Level::getDebug(), grandchild);
	}

	// Test 17: Complex hierarchy with mixed levels
	void testComplexHierarchyWithMixedLevels()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr ab = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		LoggerPtr abcd = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));
		LoggerPtr ax = hierarchy->getLogger(LOG4CXX_STR("a.x"));
		LoggerPtr axy = hierarchy->getLogger(LOG4CXX_STR("a.x.y"));

		root->setLevel(Level::getFatal());
		a->setLevel(Level::getError());
		abc->setLevel(Level::getDebug());
		ax->setLevel(Level::getInfo());

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(abcd);
		assertThresholdConsistent(ax);
		assertThresholdConsistent(axy);

		assertThresholdIs(Level::getFatal(), root);
		assertThresholdIs(Level::getError(), a);
		assertThresholdIs(Level::getError(), ab);
		assertThresholdIs(Level::getDebug(), abc);
		assertThresholdIs(Level::getDebug(), abcd);
		assertThresholdIs(Level::getInfo(), ax);
		assertThresholdIs(Level::getInfo(), axy);
	}

	// Test 18: Sibling loggers are independent
	void testSiblingLoggersIndependent()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr sibling1 = hierarchy->getLogger(LOG4CXX_STR("com.example.app1"));
		LoggerPtr sibling2 = hierarchy->getLogger(LOG4CXX_STR("com.example.app2"));
		LoggerPtr sibling3 = hierarchy->getLogger(LOG4CXX_STR("com.example.app3"));

		root->setLevel(Level::getWarn());
		sibling1->setLevel(Level::getDebug());
		sibling2->setLevel(Level::getError());
		// sibling3 inherits

		assertThresholdConsistent(sibling1);
		assertThresholdConsistent(sibling2);
		assertThresholdConsistent(sibling3);

		assertThresholdIs(Level::getDebug(), sibling1);
		assertThresholdIs(Level::getError(), sibling2);
		assertThresholdIs(Level::getWarn(), sibling3);

		// Change sibling1 - should not affect others
		sibling1->setLevel(Level::getTrace());
		assertThresholdConsistent(sibling1);
		assertThresholdConsistent(sibling2);
		assertThresholdConsistent(sibling3);

		assertThresholdIs(Level::getTrace(), sibling1);
		assertThresholdIs(Level::getError(), sibling2);
		assertThresholdIs(Level::getWarn(), sibling3);
	}

	// Test 19: Deep hierarchy inheritance
	void testDeepHierarchyInheritance()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr l1 = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr l2 = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr l3 = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		LoggerPtr l4 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));
		LoggerPtr l5 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e"));
		LoggerPtr l6 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e.f"));
		LoggerPtr l7 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e.f.g"));

		root->setLevel(Level::getInfo());

		assertThresholdConsistent(root);
		assertThresholdConsistent(l1);
		assertThresholdConsistent(l2);
		assertThresholdConsistent(l3);
		assertThresholdConsistent(l4);
		assertThresholdConsistent(l5);
		assertThresholdConsistent(l6);
		assertThresholdConsistent(l7);

		// All should inherit INFO
		assertThresholdIs(Level::getInfo(), l1);
		assertThresholdIs(Level::getInfo(), l7);

		// Set middle level
		l4->setLevel(Level::getDebug());
		assertThresholdConsistent(l1);
		assertThresholdConsistent(l2);
		assertThresholdConsistent(l3);
		assertThresholdConsistent(l4);
		assertThresholdConsistent(l5);
		assertThresholdConsistent(l6);
		assertThresholdConsistent(l7);

		assertThresholdIs(Level::getInfo(), l3);
		assertThresholdIs(Level::getDebug(), l4);
		assertThresholdIs(Level::getDebug(), l5);
		assertThresholdIs(Level::getDebug(), l7);
	}

	// Test 20: Set level to null - inherits from parent
	void testSetLevelToNullInheritsFromParent()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));

		parent->setLevel(Level::getWarn());
		child->setLevel(Level::getDebug());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getDebug(), child);

		// Set child level to null - should inherit from parent
		child->setLevel(LevelPtr());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getWarn(), child);
	}

	// Test 21: Set level to null then back to value
	void testSetLevelToNullThenBackToValue()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));

		parent->setLevel(Level::getError());
		child->setLevel(Level::getInfo());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);

		child->setLevel(LevelPtr());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getError(), child);

		child->setLevel(Level::getDebug());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getDebug(), child);

		child->setLevel(LevelPtr());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getError(), child);
	}

	// Test 22: Child set to null after parent change
	void testChildSetToNullAfterParentChange()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));

		parent->setLevel(Level::getInfo());
		child->setLevel(Level::getDebug());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);

		// Set child to null
		child->setLevel(LevelPtr());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);

		// Change parent level - child should follow
		parent->setLevel(Level::getWarn());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getWarn(), child);

		parent->setLevel(Level::getTrace());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getTrace(), child);
	}

	// Test 23: All standard levels
	void testAllStandardLevels()
	{
		LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("test"));

		LevelPtr levels[] = {
			Level::getOff(),
			Level::getFatal(),
			Level::getError(),
			Level::getWarn(),
			Level::getInfo(),
			Level::getDebug(),
			Level::getTrace(),
			Level::getAll()
		};

		for (size_t i = 0; i < sizeof(levels)/sizeof(levels[0]); ++i)
		{
			logger->setLevel(levels[i]);
			assertThresholdConsistent(logger);
			assertThresholdIs(levels[i], logger);
		}
	}

	// Test 24: Rapid level changes
	void testRapidLevelChanges()
	{
		LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("rapid"));

		for (int i = 0; i < 100; ++i)
		{
			logger->setLevel(Level::getDebug());
			assertThresholdConsistent(logger);

			logger->setLevel(Level::getInfo());
			assertThresholdConsistent(logger);

			logger->setLevel(Level::getWarn());
			assertThresholdConsistent(logger);

			logger->setLevel(Level::getError());
			assertThresholdConsistent(logger);

			logger->setLevel(LevelPtr());
			assertThresholdConsistent(logger);
		}
	}

	// Test 25: Parent and child level changes interleaved
	void testParentAndChildLevelChangesInterleaved()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("parent.child.grandchild"));

		parent->setLevel(Level::getInfo());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		child->setLevel(Level::getDebug());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		parent->setLevel(Level::getWarn());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		grandchild->setLevel(Level::getTrace());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		child->setLevel(LevelPtr());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		assertThresholdIs(Level::getWarn(), parent);
		assertThresholdIs(Level::getWarn(), child);
		assertThresholdIs(Level::getTrace(), grandchild);

		parent->setLevel(Level::getError());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		assertThresholdIs(Level::getError(), child);
		assertThresholdIs(Level::getTrace(), grandchild);
	}

	// Test 26: Logger creation order does not matter
	void testLoggerCreationOrderDoesNotMatter()
	{
		// Create in hierarchical order
		LoggerPtr a1 = hierarchy->getLogger(LOG4CXX_STR("order1"));
		LoggerPtr b1 = hierarchy->getLogger(LOG4CXX_STR("order1.child"));
		LoggerPtr c1 = hierarchy->getLogger(LOG4CXX_STR("order1.child.grandchild"));

		a1->setLevel(Level::getWarn());
		assertThresholdConsistent(a1);
		assertThresholdConsistent(b1);
		assertThresholdConsistent(c1);

		// Create in reverse order
		LoggerPtr c2 = hierarchy->getLogger(LOG4CXX_STR("order2.child.grandchild"));
		LoggerPtr b2 = hierarchy->getLogger(LOG4CXX_STR("order2.child"));
		LoggerPtr a2 = hierarchy->getLogger(LOG4CXX_STR("order2"));

		a2->setLevel(Level::getWarn());
		assertThresholdConsistent(a2);
		assertThresholdConsistent(b2);
		assertThresholdConsistent(c2);

		// Both should have same threshold
		assertThresholdIs(c1, c2);
	}

	// Test 27: Child created before parent
	void testChildCreatedBeforeParent()
	{
		// Create child first
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("parent.child.grandchild"));

		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		// Now create parent and set its level
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		parent->setLevel(Level::getInfo());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		// Child and grandchild should now inherit from parent
		assertThresholdIs(Level::getInfo(), child);
		assertThresholdIs(Level::getInfo(), grandchild);

		// Change parent level
		parent->setLevel(Level::getDebug());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		assertThresholdIs(Level::getDebug(), child);
		assertThresholdIs(Level::getDebug(), grandchild);
	}

	// Test 28: Provision node scenario
	void testProvisionNodeScenario()
	{
		// Create grandchild before intermediate parent exists
		LoggerPtr grandchild1 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));
		LoggerPtr grandchild2 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.e"));
		LoggerPtr grandchild3 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.f"));

		assertThresholdConsistent(grandchild1);
		assertThresholdConsistent(grandchild2);
		assertThresholdConsistent(grandchild3);

		// Create root ancestor
		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		a->setLevel(Level::getWarn());

		assertThresholdConsistent(a);
		assertThresholdConsistent(grandchild1);
		assertThresholdConsistent(grandchild2);
		assertThresholdConsistent(grandchild3);

		assertThresholdIs(Level::getWarn(), grandchild1);
		assertThresholdIs(Level::getWarn(), grandchild2);
		assertThresholdIs(Level::getWarn(), grandchild3);

		// Now create intermediate parent
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		abc->setLevel(Level::getDebug());

		assertThresholdConsistent(a);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(grandchild1);
		assertThresholdConsistent(grandchild2);
		assertThresholdConsistent(grandchild3);

		assertThresholdIs(Level::getWarn(), a);
		assertThresholdIs(Level::getDebug(), abc);
		assertThresholdIs(Level::getDebug(), grandchild1);
		assertThresholdIs(Level::getDebug(), grandchild2);
		assertThresholdIs(Level::getDebug(), grandchild3);

		// Override one grandchild
		grandchild2->setLevel(Level::getTrace());
		assertThresholdConsistent(grandchild2);
		assertThresholdIs(Level::getTrace(), grandchild2);

		// Change intermediate parent - should not affect overridden grandchild
		abc->setLevel(Level::getError());
		assertThresholdConsistent(abc);
		assertThresholdConsistent(grandchild1);
		assertThresholdConsistent(grandchild2);
		assertThresholdConsistent(grandchild3);

		assertThresholdIs(Level::getError(), grandchild1);
		assertThresholdIs(Level::getTrace(), grandchild2);
		assertThresholdIs(Level::getError(), grandchild3);
	}

	// Additional Test 29: Multiple children created before parent
	void testMultipleChildrenBeforeParent()
	{
		LoggerPtr child1 = hierarchy->getLogger(LOG4CXX_STR("base.child1"));
		LoggerPtr child2 = hierarchy->getLogger(LOG4CXX_STR("base.child2"));
		LoggerPtr child3 = hierarchy->getLogger(LOG4CXX_STR("base.child3"));
		LoggerPtr grandchild1 = hierarchy->getLogger(LOG4CXX_STR("base.child1.grandchild"));

		assertThresholdConsistent(child1);
		assertThresholdConsistent(child2);
		assertThresholdConsistent(child3);
		assertThresholdConsistent(grandchild1);

		// Now create parent
		LoggerPtr base = hierarchy->getLogger(LOG4CXX_STR("base"));
		base->setLevel(Level::getInfo());

		assertThresholdConsistent(base);
		assertThresholdConsistent(child1);
		assertThresholdConsistent(child2);
		assertThresholdConsistent(child3);
		assertThresholdConsistent(grandchild1);

		assertThresholdIs(Level::getInfo(), child1);
		assertThresholdIs(Level::getInfo(), child2);
		assertThresholdIs(Level::getInfo(), child3);
		assertThresholdIs(Level::getInfo(), grandchild1);
	}

	// Additional Test 30: Complex interleaved creation and level setting
	void testComplexInterleavedCreationAndLevelSetting()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getFatal());

		LoggerPtr c = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		assertThresholdConsistent(c);
		assertThresholdIs(Level::getFatal(), c);

		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		a->setLevel(Level::getError());
		assertThresholdConsistent(a);
		assertThresholdConsistent(c);
		assertThresholdIs(Level::getError(), c);

		LoggerPtr d = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));
		assertThresholdConsistent(d);
		assertThresholdIs(Level::getError(), d);

		c->setLevel(Level::getDebug());
		assertThresholdConsistent(a);
		assertThresholdConsistent(c);
		assertThresholdConsistent(d);
		assertThresholdIs(Level::getError(), a);
		assertThresholdIs(Level::getDebug(), c);
		assertThresholdIs(Level::getDebug(), d);

		LoggerPtr b = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		b->setLevel(Level::getWarn());
		assertThresholdConsistent(a);
		assertThresholdConsistent(b);
		assertThresholdConsistent(c);
		assertThresholdConsistent(d);

		assertThresholdIs(Level::getError(), a);
		assertThresholdIs(Level::getWarn(), b);
		assertThresholdIs(Level::getDebug(), c);
		assertThresholdIs(Level::getDebug(), d);

		// Set c to null - should inherit from b
		c->setLevel(LevelPtr());
		assertThresholdConsistent(c);
		assertThresholdConsistent(d);
		assertThresholdIs(Level::getWarn(), c);
		assertThresholdIs(Level::getWarn(), d);
	}

	// Additional Test 31: Wide hierarchy (many siblings)
	void testWideHierarchy()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		parent->setLevel(Level::getInfo());

		std::vector<LoggerPtr> children;
		for (int i = 0; i < 20; ++i)
		{
			std::ostringstream oss;
			oss << "parent.child" << i;
			LOG4CXX_DECODE_CHAR(category, oss.str());
			LoggerPtr child = hierarchy->getLogger(category);
			children.push_back(child);
			assertThresholdConsistent(child);
			assertThresholdIs(Level::getInfo(), child);
		}

		// Override some children
		children[5]->setLevel(Level::getDebug());
		children[10]->setLevel(Level::getWarn());
		children[15]->setLevel(Level::getError());

		for (size_t i = 0; i < children.size(); ++i)
		{
			assertThresholdConsistent(children[i]);
		}

		assertThresholdIs(Level::getDebug(), children[5]);
		assertThresholdIs(Level::getWarn(), children[10]);
		assertThresholdIs(Level::getError(), children[15]);
		assertThresholdIs(Level::getInfo(), children[0]);
		assertThresholdIs(Level::getInfo(), children[19]);

		// Change parent level
		parent->setLevel(Level::getTrace());

		for (size_t i = 0; i < children.size(); ++i)
		{
			assertThresholdConsistent(children[i]);
		}

		// Overridden children should keep their levels
		assertThresholdIs(Level::getDebug(), children[5]);
		assertThresholdIs(Level::getWarn(), children[10]);
		assertThresholdIs(Level::getError(), children[15]);
		// Non-overridden should inherit new level
		assertThresholdIs(Level::getTrace(), children[0]);
		assertThresholdIs(Level::getTrace(), children[19]);
	}

	// Additional Test 32: Deep hierarchy with alternating overrides
	void testDeepHierarchyAlternatingOverrides()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getError());

		std::vector<LoggerPtr> loggers;
		loggers.push_back(root);

		LogString name = LOG4CXX_STR("a");
		for (int i = 0; i < 10; ++i)
		{
			LoggerPtr logger = hierarchy->getLogger(name);
			loggers.push_back(logger);

			// Set level on even indices
			if (i % 2 == 0)
			{
				logger->setLevel(Level::getDebug());
			}

			assertThresholdConsistent(logger);
			name += LOG4CXX_STR(".b");
		}

		// Verify all thresholds are consistent
		for (size_t i = 0; i < loggers.size(); ++i)
		{
			assertThresholdConsistent(loggers[i]);
		}

		// Verify expected levels
		assertThresholdIs(Level::getError(), loggers[0]); // root
		assertThresholdIs(Level::getDebug(), loggers[1]); // a (i=0, even)
		assertThresholdIs(Level::getDebug(), loggers[2]); // a.b (i=1, odd, inherits)
		assertThresholdIs(Level::getDebug(), loggers[3]); // a.b.b (i=2, even)
		assertThresholdIs(Level::getDebug(), loggers[4]); // a.b.b.b (i=3, odd, inherits)
	}

	// Additional Test 33: Set parent to same parent (no-op)
	void testSetParentToSameParent()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));

		parent->setLevel(Level::getInfo());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);

		LoggerPtr currentParent = child->getParent();
		LOGUNIT_ASSERT(currentParent != nullptr);

		// Set parent to same parent (should be no-op)
		child->changeParentTo(currentParent);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);
	}

	// Additional Test 34: Root logger level changes affect entire hierarchy
	void testRootLoggerAffectsEntireHierarchy()
	{
		LoggerPtr root = hierarchy->getRootLogger();

		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr ab = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		LoggerPtr x = hierarchy->getLogger(LOG4CXX_STR("x"));
		LoggerPtr xy = hierarchy->getLogger(LOG4CXX_STR("x.y"));

		root->setLevel(Level::getWarn());

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(x);
		assertThresholdConsistent(xy);

		assertThresholdIs(Level::getWarn(), a);
		assertThresholdIs(Level::getWarn(), ab);
		assertThresholdIs(Level::getWarn(), abc);
		assertThresholdIs(Level::getWarn(), x);
		assertThresholdIs(Level::getWarn(), xy);

		root->setLevel(Level::getDebug());

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(x);
		assertThresholdConsistent(xy);

		assertThresholdIs(Level::getDebug(), a);
		assertThresholdIs(Level::getDebug(), ab);
		assertThresholdIs(Level::getDebug(), abc);
		assertThresholdIs(Level::getDebug(), x);
		assertThresholdIs(Level::getDebug(), xy);
	}

	// Additional Test 35: Mixed null and non-null levels in hierarchy
	void testMixedNullAndNonNullLevels()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr ab = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		LoggerPtr abcd = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));

		root->setLevel(Level::getError());
		a->setLevel(LevelPtr()); // null - should inherit from root
		ab->setLevel(Level::getInfo());
		abc->setLevel(LevelPtr()); // null - should inherit from ab
		abcd->setLevel(Level::getDebug());

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(abcd);

		assertThresholdIs(Level::getError(), root);
		assertThresholdIs(Level::getError(), a);
		assertThresholdIs(Level::getInfo(), ab);
		assertThresholdIs(Level::getInfo(), abc);
		assertThresholdIs(Level::getDebug(), abcd);

		// Change ab level - abc should follow
		ab->setLevel(Level::getWarn());
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(abcd);

		assertThresholdIs(Level::getWarn(), abc);
		assertThresholdIs(Level::getDebug(), abcd);
	}

	// Additional Test 36: Verify threshold after multiple parent changes
	void testThresholdAfterMultipleParentChanges()
	{
		LoggerPtr p1 = hierarchy->getLogger(LOG4CXX_STR("parent1"));
		LoggerPtr p2 = hierarchy->getLogger(LOG4CXX_STR("parent2"));
		LoggerPtr p3 = hierarchy->getLogger(LOG4CXX_STR("parent3"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("orphan"));

		p1->setLevel(Level::getTrace());
		p2->setLevel(Level::getInfo());
		p3->setLevel(Level::getFatal());

		child->changeParentTo(p1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getTrace(), child);

		child->changeParentTo(p2);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);

		child->changeParentTo(p3);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getFatal(), child);

		child->changeParentTo(p1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getTrace(), child);

		// Set child's own level
		child->setLevel(Level::getWarn());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getWarn(), child);

		// Change parent - child should keep its level
		child->changeParentTo(p2);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getWarn(), child);
	}

	// Additional Test 37: Grandchild created before parent and middle ancestor
	void testGrandchildBeforeParentAndMiddle()
	{
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e.f"));
		assertThresholdConsistent(grandchild);

		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getError());
		assertThresholdConsistent(grandchild);
		assertThresholdIs(Level::getError(), grandchild);

		LoggerPtr middle = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		middle->setLevel(Level::getInfo());
		assertThresholdConsistent(middle);
		assertThresholdConsistent(grandchild);
		assertThresholdIs(Level::getInfo(), grandchild);

		LoggerPtr top = hierarchy->getLogger(LOG4CXX_STR("a"));
		top->setLevel(Level::getWarn());
		assertThresholdConsistent(top);
		assertThresholdConsistent(middle);
		assertThresholdConsistent(grandchild);

		// grandchild should still inherit from middle (closest ancestor with level)
		assertThresholdIs(Level::getWarn(), top);
		assertThresholdIs(Level::getInfo(), middle);
		assertThresholdIs(Level::getInfo(), grandchild);
	}

	// Additional Test 38: Stress test - many level changes
	void testStressTestManyLevelChanges()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("stress.parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("stress.parent.child"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("stress.parent.child.grandchild"));

		LevelPtr levels[] = {
			Level::getTrace(),
			Level::getDebug(),
			Level::getInfo(),
			Level::getWarn(),
			Level::getError(),
			Level::getFatal()
		};

		for (int iteration = 0; iteration < 50; ++iteration)
		{
			for (size_t i = 0; i < sizeof(levels)/sizeof(levels[0]); ++i)
			{
				root->setLevel(levels[i]);
				assertThresholdConsistent(root);
				assertThresholdConsistent(parent);
				assertThresholdConsistent(child);
				assertThresholdConsistent(grandchild);

				parent->setLevel(levels[(i + 1) % (sizeof(levels)/sizeof(levels[0]))]);
				assertThresholdConsistent(parent);
				assertThresholdConsistent(child);
				assertThresholdConsistent(grandchild);

				child->setLevel(levels[(i + 2) % (sizeof(levels)/sizeof(levels[0]))]);
				assertThresholdConsistent(child);
				assertThresholdConsistent(grandchild);

				// Set to null and verify inheritance
				child->setLevel(LevelPtr());
				assertThresholdConsistent(child);
				assertThresholdConsistent(grandchild);
			}
		}
	}

	// Additional Test 39: Verify consistency across different name patterns
	void testDifferentNamePatterns()
	{
		// Single segment names
		LoggerPtr single1 = hierarchy->getLogger(LOG4CXX_STR("logger1"));
		LoggerPtr single2 = hierarchy->getLogger(LOG4CXX_STR("logger2"));

		// Multi-segment names
		LoggerPtr multi1 = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));
		LoggerPtr multi2 = hierarchy->getLogger(LOG4CXX_STR("org.apache.log4cxx"));

		// Very long names
		LoggerPtr longName = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p"));

		// Names with numbers
		LoggerPtr numbered = hierarchy->getLogger(LOG4CXX_STR("logger.v1.module2.class3"));

		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getInfo());

		assertThresholdConsistent(single1);
		assertThresholdConsistent(single2);
		assertThresholdConsistent(multi1);
		assertThresholdConsistent(multi2);
		assertThresholdConsistent(longName);
		assertThresholdConsistent(numbered);

		single1->setLevel(Level::getDebug());
		assertThresholdConsistent(single1);

		LoggerPtr comExample = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		comExample->setLevel(Level::getWarn());
		assertThresholdConsistent(comExample);
		assertThresholdConsistent(multi1);
		assertThresholdIs(Level::getWarn(), multi1);
	}

	// Additional Test 40: Parent chain with all null levels except root
	void testParentChainAllNullExceptRoot()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr ab = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		LoggerPtr abcd = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));

		root->setLevel(Level::getWarn());
		// All others have null level (default)

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(abcd);

		// All should inherit from root
		assertThresholdIs(Level::getWarn(), a);
		assertThresholdIs(Level::getWarn(), ab);
		assertThresholdIs(Level::getWarn(), abc);
		assertThresholdIs(Level::getWarn(), abcd);

		// Change root
		root->setLevel(Level::getDebug());

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(abcd);

		assertThresholdIs(Level::getDebug(), a);
		assertThresholdIs(Level::getDebug(), ab);
		assertThresholdIs(Level::getDebug(), abc);
		assertThresholdIs(Level::getDebug(), abcd);
	}

	// Additional Test 41: Concurrent hierarchy branches
	void testConcurrentHierarchyBranches()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getError());

		// Branch 1: com.example.app
		LoggerPtr com = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr comExample = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr comExampleApp = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));

		// Branch 2: org.apache.log4cxx
		LoggerPtr org = hierarchy->getLogger(LOG4CXX_STR("org"));
		LoggerPtr orgApache = hierarchy->getLogger(LOG4CXX_STR("org.apache"));
		LoggerPtr orgApacheLog4cxx = hierarchy->getLogger(LOG4CXX_STR("org.apache.log4cxx"));

		// Set different levels on branches
		com->setLevel(Level::getInfo());
		org->setLevel(Level::getDebug());

		assertThresholdConsistent(com);
		assertThresholdConsistent(comExample);
		assertThresholdConsistent(comExampleApp);
		assertThresholdConsistent(org);
		assertThresholdConsistent(orgApache);
		assertThresholdConsistent(orgApacheLog4cxx);

		assertThresholdIs(Level::getInfo(), comExample);
		assertThresholdIs(Level::getInfo(), comExampleApp);
		assertThresholdIs(Level::getDebug(), orgApache);
		assertThresholdIs(Level::getDebug(), orgApacheLog4cxx);

		// Override in middle of one branch
		comExample->setLevel(Level::getWarn());
		assertThresholdConsistent(comExample);
		assertThresholdConsistent(comExampleApp);

		assertThresholdIs(Level::getWarn(), comExample);
		assertThresholdIs(Level::getWarn(), comExampleApp);

		// Other branch should be unaffected
		assertThresholdConsistent(org);
		assertThresholdConsistent(orgApache);
		assertThresholdConsistent(orgApacheLog4cxx);
		assertThresholdIs(Level::getDebug(), orgApache);
	}

	// Additional Test 42: Setting level on logger with existing children
	void testSetLevelOnLoggerWithExistingChildren()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child1 = hierarchy->getLogger(LOG4CXX_STR("parent.child1"));
		LoggerPtr child2 = hierarchy->getLogger(LOG4CXX_STR("parent.child2"));
		LoggerPtr grandchild1 = hierarchy->getLogger(LOG4CXX_STR("parent.child1.grandchild"));
		LoggerPtr grandchild2 = hierarchy->getLogger(LOG4CXX_STR("parent.child2.grandchild"));

		// All start with root's level
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getError());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child1);
		assertThresholdConsistent(child2);
		assertThresholdConsistent(grandchild1);
		assertThresholdConsistent(grandchild2);

		// Set parent level - should propagate to all children
		parent->setLevel(Level::getInfo());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child1);
		assertThresholdConsistent(child2);
		assertThresholdConsistent(grandchild1);
		assertThresholdConsistent(grandchild2);

		assertThresholdIs(Level::getInfo(), child1);
		assertThresholdIs(Level::getInfo(), child2);
		assertThresholdIs(Level::getInfo(), grandchild1);
		assertThresholdIs(Level::getInfo(), grandchild2);

		// Override one child
		child1->setLevel(Level::getDebug());
		assertThresholdConsistent(child1);
		assertThresholdConsistent(grandchild1);

		assertThresholdIs(Level::getDebug(), child1);
		assertThresholdIs(Level::getDebug(), grandchild1);

		// Change parent again - overridden child should keep its level
		parent->setLevel(Level::getWarn());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child1);
		assertThresholdConsistent(child2);
		assertThresholdConsistent(grandchild1);
		assertThresholdConsistent(grandchild2);

		assertThresholdIs(Level::getDebug(), child1);
		assertThresholdIs(Level::getWarn(), child2);
		assertThresholdIs(Level::getDebug(), grandchild1);
		assertThresholdIs(Level::getWarn(), grandchild2);
	}

	// Additional Test 43: Alternating setLevel and changeParentTo calls
	void testAlternatingSetLevelAndSetParent()
	{
		LoggerPtr p1 = hierarchy->getLogger(LOG4CXX_STR("p1"));
		LoggerPtr p2 = hierarchy->getLogger(LOG4CXX_STR("p2"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));

		p1->setLevel(Level::getInfo());
		assertThresholdConsistent(p1);

		child->changeParentTo(p1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);

		child->setLevel(Level::getDebug());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getDebug(), child);

		p2->setLevel(Level::getWarn());
		assertThresholdConsistent(p2);

		child->changeParentTo(p2);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getDebug(), child); // Keeps own level

		child->setLevel(LevelPtr());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getWarn(), child); // Now inherits from p2

		child->changeParentTo(p1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child); // Now inherits from p1

		p1->setLevel(Level::getError());
		assertThresholdConsistent(p1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getError(), child);
	}

	// Additional Test 44: Verify threshold with OFF and ALL levels
	void testOffAndAllLevels()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));

		parent->setLevel(Level::getOff());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getOff(), parent);
		assertThresholdIs(Level::getOff(), child);

		parent->setLevel(Level::getAll());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getAll(), parent);
		assertThresholdIs(Level::getAll(), child);

		child->setLevel(Level::getOff());
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getOff(), child);

		parent->setLevel(Level::getTrace());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getTrace(), parent);
		assertThresholdIs(Level::getOff(), child); // Keeps OFF
	}

	// Additional Test 45: Complex scenario with provision nodes and level changes
	void testComplexProvisionNodeScenario()
	{
		// Create deep child first
		LoggerPtr deepChild = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e.f.g"));
		assertThresholdConsistent(deepChild);

		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getFatal());
		assertThresholdConsistent(deepChild);
		assertThresholdIs(Level::getFatal(), deepChild);

		// Create intermediate ancestors in random order
		LoggerPtr c = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		c->setLevel(Level::getError());
		assertThresholdConsistent(c);
		assertThresholdConsistent(deepChild);
		assertThresholdIs(Level::getError(), deepChild);

		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		a->setLevel(Level::getWarn());
		assertThresholdConsistent(a);
		assertThresholdConsistent(c);
		assertThresholdConsistent(deepChild);
		assertThresholdIs(Level::getWarn(), a);
		assertThresholdIs(Level::getError(), c);
		assertThresholdIs(Level::getError(), deepChild);

		LoggerPtr e = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e"));
		e->setLevel(Level::getDebug());
		assertThresholdConsistent(e);
		assertThresholdConsistent(deepChild);
		assertThresholdIs(Level::getDebug(), e);
		assertThresholdIs(Level::getDebug(), deepChild);

		LoggerPtr b = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		b->setLevel(Level::getInfo());
		assertThresholdConsistent(b);
		assertThresholdConsistent(c);
		assertThresholdConsistent(e);
		assertThresholdConsistent(deepChild);

		assertThresholdIs(Level::getInfo(), b);
		assertThresholdIs(Level::getError(), c);
		assertThresholdIs(Level::getDebug(), e);
		assertThresholdIs(Level::getDebug(), deepChild);

		// Set e to null - deepChild should inherit from c
		e->setLevel(LevelPtr());
		assertThresholdConsistent(e);
		assertThresholdConsistent(deepChild);
		assertThresholdIs(Level::getError(), e);
		assertThresholdIs(Level::getError(), deepChild);
	}

	// Additional Test 46: Multiple siblings with different levels
	void testMultipleSiblingsWithDifferentLevels()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		parent->setLevel(Level::getInfo());

		std::vector<LoggerPtr> siblings;
		LevelPtr levels[] = {
			Level::getTrace(),
			Level::getDebug(),
			LevelPtr(), // null - inherits
			Level::getWarn(),
			Level::getError(),
			LevelPtr(), // null - inherits
			Level::getFatal()
		};

		for (size_t i = 0; i < sizeof(levels)/sizeof(levels[0]); ++i)
		{
			std::ostringstream oss;
			oss << "parent.sibling" << i;
			LOG4CXX_DECODE_CHAR(category, oss.str());
			LoggerPtr sibling = hierarchy->getLogger(category);
			sibling->setLevel(levels[i]);
			siblings.push_back(sibling);
			assertThresholdConsistent(sibling);
		}

		// Verify each sibling has correct threshold
		assertThresholdIs(Level::getTrace(), siblings[0]);
		assertThresholdIs(Level::getDebug(), siblings[1]);
		assertThresholdIs(Level::getInfo(), siblings[2]); // inherits
		assertThresholdIs(Level::getWarn(), siblings[3]);
		assertThresholdIs(Level::getError(), siblings[4]);
		assertThresholdIs(Level::getInfo(), siblings[5]); // inherits
		assertThresholdIs(Level::getFatal(), siblings[6]);

		// Change parent level
		parent->setLevel(Level::getDebug());

		for (size_t i = 0; i < siblings.size(); ++i)
		{
			assertThresholdConsistent(siblings[i]);
		}

		// Only inheriting siblings should change
		assertThresholdIs(Level::getTrace(), siblings[0]);
		assertThresholdIs(Level::getDebug(), siblings[1]);
		assertThresholdIs(Level::getDebug(), siblings[2]); // changed
		assertThresholdIs(Level::getWarn(), siblings[3]);
		assertThresholdIs(Level::getError(), siblings[4]);
		assertThresholdIs(Level::getDebug(), siblings[5]); // changed
		assertThresholdIs(Level::getFatal(), siblings[6]);
	}

	// Additional Test 47: Parent chain with gaps
	void testParentChainWithGaps()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getError());

		// Create loggers with gaps in hierarchy
		LoggerPtr level2 = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr level5 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e"));

		assertThresholdConsistent(level2);
		assertThresholdConsistent(level5);

		// Both should inherit from root
		assertThresholdIs(Level::getError(), level2);
		assertThresholdIs(Level::getError(), level5);

		// Set level on level2
		level2->setLevel(Level::getInfo());
		assertThresholdConsistent(level2);
		assertThresholdConsistent(level5);

		// level5 should now inherit from level2
		assertThresholdIs(Level::getInfo(), level5);

		// Fill in a gap
		LoggerPtr level3 = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		level3->setLevel(Level::getDebug());
		assertThresholdConsistent(level3);
		assertThresholdConsistent(level5);

		// level5 should now inherit from level3
		assertThresholdIs(Level::getDebug(), level5);

		// Fill in another gap
		LoggerPtr level4 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));
		assertThresholdConsistent(level4);
		assertThresholdConsistent(level5);

		// level4 and level5 should inherit from level3
		assertThresholdIs(Level::getDebug(), level4);
		assertThresholdIs(Level::getDebug(), level5);
	}

	// Additional Test 48: Verify threshold after hierarchy reset
	void testThresholdAfterHierarchyOperations()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));

		parent->setLevel(Level::getInfo());
		child->setLevel(Level::getDebug());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);

		assertThresholdIs(Level::getInfo(), parent);
		assertThresholdIs(Level::getDebug(), child);

		// After getting effective level, threshold should still be consistent
		LevelPtr effectiveLevel = child->getEffectiveLevel();
		assertThresholdConsistent(child);
		assertThresholdIs(effectiveLevel, child);
	}

	// Additional Test 49: Cross-branch hierarchy changes
	void testCrossBranchHierarchyChanges()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getWarn());

		// Branch A
		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr ab = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));

		// Branch X
		LoggerPtr x = hierarchy->getLogger(LOG4CXX_STR("x"));
		LoggerPtr xy = hierarchy->getLogger(LOG4CXX_STR("x.y"));
		LoggerPtr xyz = hierarchy->getLogger(LOG4CXX_STR("x.y.z"));

		a->setLevel(Level::getInfo());
		x->setLevel(Level::getDebug());

		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(x);
		assertThresholdConsistent(xy);
		assertThresholdConsistent(xyz);

		assertThresholdIs(Level::getInfo(), ab);
		assertThresholdIs(Level::getInfo(), abc);
		assertThresholdIs(Level::getDebug(), xy);
		assertThresholdIs(Level::getDebug(), xyz);

		// Change root - should affect both branches (where not overridden)
		root->setLevel(Level::getError());

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(x);
		assertThresholdConsistent(xy);
		assertThresholdConsistent(xyz);

		// Branch A still has its override
		assertThresholdIs(Level::getInfo(), a);
		assertThresholdIs(Level::getInfo(), ab);
		assertThresholdIs(Level::getInfo(), abc);

		// Branch X still has its override
		assertThresholdIs(Level::getDebug(), x);
		assertThresholdIs(Level::getDebug(), xy);
		assertThresholdIs(Level::getDebug(), xyz);

		// Set middle of branch A to null
		a->setLevel(LevelPtr());
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);

		// Branch A should now inherit from root
		assertThresholdIs(Level::getError(), a);
		assertThresholdIs(Level::getError(), ab);
		assertThresholdIs(Level::getError(), abc);

		// Branch X should be unaffected
		assertThresholdIs(Level::getDebug(), x);
		assertThresholdIs(Level::getDebug(), xy);
		assertThresholdIs(Level::getDebug(), xyz);
	}

	// Additional Test 50: Verify threshold with extremely deep hierarchy
	void testExtremelyDeepHierarchy()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getWarn());

		std::string name = "level";
		LoggerPtr previous = root;
		std::vector<LoggerPtr> loggers;

		// Create 50-level deep hierarchy
		for (int i = 1; i <= 50; ++i)
		{
			std::ostringstream oss;
			oss << name << '.' << i;
			name = oss.str();
			LOG4CXX_DECODE_CHAR(category, name);
			LoggerPtr logger = hierarchy->getLogger(category);
			loggers.push_back(logger);
			assertThresholdConsistent(logger);
			assertThresholdIs(Level::getWarn(), logger);
		}

		// Set level at depth 25
		loggers[24]->setLevel(Level::getDebug());

		// Verify all loggers
		for (size_t i = 0; i < loggers.size(); ++i)
		{
			assertThresholdConsistent(loggers[i]);

			if (i < 24)
			{
				assertThresholdIs(Level::getWarn(), loggers[i]);
			}
			else
			{
				assertThresholdIs(Level::getDebug(), loggers[i]);
			}
		}

		// Set level at depth 40
		loggers[39]->setLevel(Level::getTrace());

		for (size_t i = 0; i < loggers.size(); ++i)
		{
			assertThresholdConsistent(loggers[i]);

			if (i < 24)
			{
				assertThresholdIs(Level::getWarn(), loggers[i]);
			}
			else if (i < 39)
			{
				assertThresholdIs(Level::getDebug(), loggers[i]);
			}
			else
			{
				assertThresholdIs(Level::getTrace(), loggers[i]);
			}
		}

		// Change root level
		root->setLevel(Level::getError());

		for (size_t i = 0; i < loggers.size(); ++i)
		{
			assertThresholdConsistent(loggers[i]);

			if (i < 24)
			{
				assertThresholdIs(Level::getError(), loggers[i]);
			}
			else if (i < 39)
			{
				assertThresholdIs(Level::getDebug(), loggers[i]);
			}
			else
			{
				assertThresholdIs(Level::getTrace(), loggers[i]);
			}
		}
	}

	// Additional Test 51: Verify threshold consistency during logger retrieval
	void testThresholdConsistencyDuringRetrieval()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getInfo());

		// Get logger multiple times and verify consistency each time
		for (int i = 0; i < 10; ++i)
		{
			LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("test.logger"));
			assertThresholdConsistent(logger);
			assertThresholdIs(Level::getInfo(), logger);
		}

		// Set level on the logger
		LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("test.logger"));
		logger->setLevel(Level::getDebug());

		// Get it again and verify
		for (int i = 0; i < 10; ++i)
		{
			LoggerPtr sameLogger = hierarchy->getLogger(LOG4CXX_STR("test.logger"));
			assertThresholdConsistent(sameLogger);
			assertThresholdIs(Level::getDebug(), sameLogger);
		}
	}

	// Additional Test 52: Threshold consistency with logger factory
	void testThresholdConsistencyWithLoggerFactory()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getWarn());
		spi::LoggerFactoryPtr factory =
#if LOG4CXX_ABI_VERSION <= 15
			std::make_shared<DefaultLoggerFactory>();
#else
			std::make_shared<spi::LoggerFactory>();
#endif
		LoggerPtr logger1 = hierarchy->getLogger(LOG4CXX_STR("factory.test1"), factory);
		LoggerPtr logger2 = hierarchy->getLogger(LOG4CXX_STR("factory.test2"), factory);

		assertThresholdConsistent(logger1);
		assertThresholdConsistent(logger2);

		assertThresholdIs(Level::getWarn(), logger1);
		assertThresholdIs(Level::getWarn(), logger2);

		logger1->setLevel(Level::getDebug());
		assertThresholdConsistent(logger1);
		assertThresholdConsistent(logger2);

		assertThresholdIs(Level::getDebug(), logger1);
		assertThresholdIs(Level::getWarn(), logger2);
	}

	// Additional Test 53: Verify threshold after parent-child swap
	void testThresholdAfterParentChildSwap()
	{
		LoggerPtr logger1 = hierarchy->getLogger(LOG4CXX_STR("swap.test1"));
		LoggerPtr logger2 = hierarchy->getLogger(LOG4CXX_STR("swap.test2"));

		logger1->setLevel(Level::getInfo());
		logger2->setLevel(Level::getDebug());

		assertThresholdConsistent(logger1);
		assertThresholdConsistent(logger2);

		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));

		// Set logger1 as parent
		child->changeParentTo(logger1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);

		// Swap to logger2 as parent
		child->changeParentTo(logger2);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getDebug(), child);

		// Swap back to logger1
		child->changeParentTo(logger1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);

		// Change logger1's level while it's the parent
		logger1->setLevel(Level::getWarn());
		assertThresholdConsistent(logger1);
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getWarn(), child);
	}

	// Additional Test 54: Threshold with all levels set to same value
	void testThresholdWithAllSameLevel()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr ab = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));

		// Set all to same level
		LevelPtr sameLevel = Level::getInfo();
		root->setLevel(sameLevel);
		a->setLevel(sameLevel);
		ab->setLevel(sameLevel);
		abc->setLevel(sameLevel);

		assertThresholdConsistent(root);
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);

		assertThresholdIs(Level::getInfo(), root);
		assertThresholdIs(Level::getInfo(), a);
		assertThresholdIs(Level::getInfo(), ab);
		assertThresholdIs(Level::getInfo(), abc);

		// Set middle one to null - should still be INFO
		ab->setLevel(LevelPtr());
		assertThresholdConsistent(ab);
		assertThresholdIs(Level::getInfo(), ab);
	}

	// Additional Test 55: Threshold after rapid parent reassignments
	void testThresholdAfterRapidParentReassignments()
	{
		LoggerPtr p1 = hierarchy->getLogger(LOG4CXX_STR("p1"));
		LoggerPtr p2 = hierarchy->getLogger(LOG4CXX_STR("p2"));
		LoggerPtr p3 = hierarchy->getLogger(LOG4CXX_STR("p3"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));

		p1->setLevel(Level::getTrace());
		p2->setLevel(Level::getDebug());
		p3->setLevel(Level::getInfo());

		for (int i = 0; i < 100; ++i)
		{
			child->changeParentTo(p1);
			assertThresholdConsistent(child);
			assertThresholdIs(Level::getTrace(), child);

			child->changeParentTo(p2);
			assertThresholdConsistent(child);
			assertThresholdIs(Level::getDebug(), child);

			child->changeParentTo(p3);
			assertThresholdConsistent(child);
			assertThresholdIs(Level::getInfo(), child);
		}
	}

	// Additional Test 56: Threshold with zigzag level pattern
	void testThresholdWithZigzagLevelPattern()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		LoggerPtr l1 = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr l2 = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr l3 = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		LoggerPtr l4 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));
		LoggerPtr l5 = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e"));

		// Set zigzag pattern: high, low, high, low, high
		root->setLevel(Level::getError());   // high
		l1->setLevel(Level::getDebug());     // low
		l2->setLevel(Level::getWarn());      // high
		l3->setLevel(Level::getTrace());     // low
		l4->setLevel(Level::getFatal());     // high

		assertThresholdConsistent(root);
		assertThresholdConsistent(l1);
		assertThresholdConsistent(l2);
		assertThresholdConsistent(l3);
		assertThresholdConsistent(l4);
		assertThresholdConsistent(l5);

		assertThresholdIs(Level::getError(), root);
		assertThresholdIs(Level::getDebug(), l1);
		assertThresholdIs(Level::getWarn(), l2);
		assertThresholdIs(Level::getTrace(), l3);
		assertThresholdIs(Level::getFatal(), l4);
		assertThresholdIs(Level::getFatal(), l5); // inherits from l4
	}

	// Additional Test 57: Threshold after removing and re-adding levels
	void testThresholdAfterRemovingAndReaddingLevels()
	{
		LoggerPtr parent = hierarchy->getLogger(LOG4CXX_STR("parent"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("parent.child"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("parent.child.grandchild"));

		parent->setLevel(Level::getWarn());
		child->setLevel(Level::getDebug());

		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		assertThresholdIs(Level::getWarn(), parent);
		assertThresholdIs(Level::getDebug(), child);
		assertThresholdIs(Level::getDebug(), grandchild);

		// Remove child's level
		child->setLevel(LevelPtr());
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);
		assertThresholdIs(Level::getWarn(), child);
		assertThresholdIs(Level::getWarn(), grandchild);

		// Re-add child's level
		child->setLevel(Level::getInfo());
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);
		assertThresholdIs(Level::getInfo(), child);
		assertThresholdIs(Level::getInfo(), grandchild);

		// Remove parent's level
		parent->setLevel(LevelPtr());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);

		// Parent should inherit from root, child keeps its level
		LoggerPtr root = hierarchy->getRootLogger();
		assertThresholdIs(root->getEffectiveLevel(), parent);
		assertThresholdIs(Level::getInfo(), child);
		assertThresholdIs(Level::getInfo(), grandchild);

		// Re-add parent's level
		parent->setLevel(Level::getError());
		assertThresholdConsistent(parent);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);
		assertThresholdIs(Level::getError(), parent);
		assertThresholdIs(Level::getInfo(), child);
		assertThresholdIs(Level::getInfo(), grandchild);
	}

	// Additional Test 58: Threshold consistency with diamond-shaped hierarchy
	void testThresholdWithDiamondHierarchy()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getError());

		// Create diamond pattern
		LoggerPtr top = hierarchy->getLogger(LOG4CXX_STR("top"));
		LoggerPtr left = hierarchy->getLogger(LOG4CXX_STR("top.left"));
		LoggerPtr right = hierarchy->getLogger(LOG4CXX_STR("top.right"));
		LoggerPtr bottom = hierarchy->getLogger(LOG4CXX_STR("top.left.bottom"));

		// Note: bottom can only have one parent in the hierarchy
		// It will be under "top.left" by its name

		top->setLevel(Level::getWarn());
		left->setLevel(Level::getInfo());
		right->setLevel(Level::getDebug());

		assertThresholdConsistent(root);
		assertThresholdConsistent(top);
		assertThresholdConsistent(left);
		assertThresholdConsistent(right);
		assertThresholdConsistent(bottom);

		assertThresholdIs(Level::getWarn(), top);
		assertThresholdIs(Level::getInfo(), left);
		assertThresholdIs(Level::getDebug(), right);
		assertThresholdIs(Level::getInfo(), bottom); // inherits from left

		// Change top level
		top->setLevel(Level::getTrace());
		assertThresholdConsistent(top);
		assertThresholdConsistent(left);
		assertThresholdConsistent(right);
		assertThresholdConsistent(bottom);

		// left, right, and bottom should keep their levels
		assertThresholdIs(Level::getTrace(), top);
		assertThresholdIs(Level::getInfo(), left);
		assertThresholdIs(Level::getDebug(), right);
		assertThresholdIs(Level::getInfo(), bottom);
	}

	// Additional Test 59: Threshold with very long logger names
	void testThresholdWithVeryLongLoggerNames()
	{
		LogString longName = LOG4CXX_STR("very.long.logger.name.with.many.segments.to.test.the.hierarchy");
		longName += LOG4CXX_STR(".and.even.more.segments.to.make.it.really.long.and.complex");
		longName += LOG4CXX_STR(".final.segment.at.the.end");

		LoggerPtr logger = hierarchy->getLogger(longName);
		assertThresholdConsistent(logger);

		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getInfo());
		assertThresholdConsistent(logger);
		assertThresholdIs(Level::getInfo(), logger);

		// Set level on intermediate ancestor
		LoggerPtr intermediate = hierarchy->getLogger(LOG4CXX_STR("very.long.logger.name.with.many"));
		intermediate->setLevel(Level::getDebug());
		assertThresholdConsistent(intermediate);
		assertThresholdConsistent(logger);
		assertThresholdIs(Level::getDebug(), logger);

		// Set level on the long logger itself
		logger->setLevel(Level::getWarn());
		assertThresholdConsistent(logger);
		assertThresholdIs(Level::getWarn(), logger);
	}

	// Additional Test 60: Threshold after setting same level multiple times
	void testThresholdAfterSettingSameLevelMultipleTimes()
	{
		LoggerPtr logger = hierarchy->getLogger(LOG4CXX_STR("test"));

		for (int i = 0; i < 50; ++i)
		{
			logger->setLevel(Level::getInfo());
			assertThresholdConsistent(logger);
			assertThresholdIs(Level::getInfo(), logger);
		}

		logger->setLevel(Level::getDebug());
		assertThresholdConsistent(logger);
		assertThresholdIs(Level::getDebug(), logger);

		for (int i = 0; i < 50; ++i)
		{
			logger->setLevel(Level::getDebug());
			assertThresholdConsistent(logger);
			assertThresholdIs(Level::getDebug(), logger);
		}
	}

	// Additional Test 61: Complex scenario mixing all operations
	void testComplexMixedOperations()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getWarn());

		// Create loggers in mixed order
		LoggerPtr deep = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e.f"));
		assertThresholdConsistent(deep);

		LoggerPtr mid = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		mid->setLevel(Level::getInfo());
		assertThresholdConsistent(mid);
		assertThresholdConsistent(deep);

		LoggerPtr top = hierarchy->getLogger(LOG4CXX_STR("a"));
		top->setLevel(Level::getError());
		assertThresholdConsistent(top);
		assertThresholdConsistent(mid);
		assertThresholdConsistent(deep);

		assertThresholdIs(Level::getError(), top);
		assertThresholdIs(Level::getInfo(), mid);
		assertThresholdIs(Level::getInfo(), deep);

		// Set deep's level
		deep->setLevel(Level::getDebug());
		assertThresholdConsistent(deep);
		assertThresholdIs(Level::getDebug(), deep);

		// Create sibling
		LoggerPtr sibling = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d.e.g"));
		assertThresholdConsistent(sibling);
		assertThresholdIs(Level::getInfo(), sibling);

		// Change mid to null
		mid->setLevel(LevelPtr());
		assertThresholdConsistent(mid);
		assertThresholdConsistent(deep);
		assertThresholdConsistent(sibling);

		assertThresholdIs(Level::getError(), mid);
		assertThresholdIs(Level::getDebug(), deep);
		assertThresholdIs(Level::getError(), sibling);

		// Change top
		top->setLevel(Level::getTrace());
		assertThresholdConsistent(top);
		assertThresholdConsistent(mid);
		assertThresholdConsistent(deep);
		assertThresholdConsistent(sibling);

		assertThresholdIs(Level::getTrace(), top);
		assertThresholdIs(Level::getTrace(), mid);
		assertThresholdIs(Level::getDebug(), deep);
		assertThresholdIs(Level::getTrace(), sibling);

		// Create intermediate logger
		LoggerPtr intermediate = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		intermediate->setLevel(Level::getFatal());
		assertThresholdConsistent(intermediate);
		assertThresholdConsistent(mid);
		assertThresholdConsistent(deep);
		assertThresholdConsistent(sibling);

		assertThresholdIs(Level::getFatal(), intermediate);
		assertThresholdIs(Level::getFatal(), mid);
		assertThresholdIs(Level::getDebug(), deep);
		assertThresholdIs(Level::getFatal(), sibling);
	}

	// Additional Test 62: Threshold after parent change with grandchildren
	void testThresholdAfterParentChangeWithGrandchildren()
	{
		LoggerPtr p1 = hierarchy->getLogger(LOG4CXX_STR("p1"));
		LoggerPtr p2 = hierarchy->getLogger(LOG4CXX_STR("p2"));
		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));
		LoggerPtr grandchild = hierarchy->getLogger(LOG4CXX_STR("child.grandchild"));
		LoggerPtr greatGrandchild = hierarchy->getLogger(LOG4CXX_STR("child.grandchild.great"));

		p1->setLevel(Level::getInfo());
		p2->setLevel(Level::getError());

		child->changeParentTo(p1);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);
		assertThresholdConsistent(greatGrandchild);

		assertThresholdIs(Level::getInfo(), child);
		assertThresholdIs(Level::getInfo(), grandchild);
		assertThresholdIs(Level::getInfo(), greatGrandchild);

		// Change parent - all descendants should update
		child->changeParentTo(p2);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);
		assertThresholdConsistent(greatGrandchild);

		assertThresholdIs(Level::getError(), child);
		assertThresholdIs(Level::getError(), grandchild);
		assertThresholdIs(Level::getError(), greatGrandchild);

		// Set grandchild's level
		grandchild->setLevel(Level::getDebug());
		assertThresholdConsistent(grandchild);
		assertThresholdConsistent(greatGrandchild);

		assertThresholdIs(Level::getDebug(), grandchild);
		assertThresholdIs(Level::getDebug(), greatGrandchild);

		// Change child's parent again - grandchild should keep its level
		child->changeParentTo(p1);
		assertThresholdConsistent(child);
		assertThresholdConsistent(grandchild);
		assertThresholdConsistent(greatGrandchild);

		assertThresholdIs(Level::getInfo(), child);
		assertThresholdIs(Level::getDebug(), grandchild);
		assertThresholdIs(Level::getDebug(), greatGrandchild);
	}

	// Additional Test 63: Verify threshold with empty logger name
	void testThresholdWithEmptyLoggerName()
	{
		// Root logger has empty name
		LoggerPtr root = hierarchy->getRootLogger();
		root->setLevel(Level::getInfo());
		assertThresholdConsistent(root);
		assertThresholdIs(Level::getInfo(), root);

		LoggerPtr child = hierarchy->getLogger(LOG4CXX_STR("child"));
		assertThresholdConsistent(child);
		assertThresholdIs(Level::getInfo(), child);
	}

	// Additional Test 64: Threshold with single character logger names
	void testThresholdWithSingleCharacterNames()
	{
		LoggerPtr a = hierarchy->getLogger(LOG4CXX_STR("a"));
		LoggerPtr ab = hierarchy->getLogger(LOG4CXX_STR("a.b"));
		LoggerPtr abc = hierarchy->getLogger(LOG4CXX_STR("a.b.c"));
		LoggerPtr abcd = hierarchy->getLogger(LOG4CXX_STR("a.b.c.d"));

		a->setLevel(Level::getWarn());
		assertThresholdConsistent(a);
		assertThresholdConsistent(ab);
		assertThresholdConsistent(abc);
		assertThresholdConsistent(abcd);

		assertThresholdIs(Level::getWarn(), ab);
		assertThresholdIs(Level::getWarn(), abc);
		assertThresholdIs(Level::getWarn(), abcd);

		abc->setLevel(Level::getDebug());
		assertThresholdConsistent(abc);
		assertThresholdConsistent(abcd);

		assertThresholdIs(Level::getDebug(), abc);
		assertThresholdIs(Level::getDebug(), abcd);
	}

	// Additional Test 65: Final comprehensive stress test
	void testFinalComprehensiveStressTest()
	{
		LoggerPtr root = hierarchy->getRootLogger();
		std::vector<LoggerPtr> allLoggers;

		// Create complex hierarchy
		std::string bases[] = {"com", "org", "net", "edu"};
		std::string mids[] = {"example", "apache", "test", "demo"};
		std::string ends[] = {"app", "service", "module", "component"};

		for (size_t i = 0; i < sizeof(bases)/sizeof(bases[0]); ++i)
		{
			for (size_t j = 0; j < sizeof(mids)/sizeof(mids[0]); ++j)
			{
				for (size_t k = 0; k < sizeof(ends)/sizeof(ends[0]); ++k)
				{
					std::ostringstream oss;
					oss << bases[i] << "." << mids[j] << "." << ends[k];
					LOG4CXX_DECODE_CHAR(category, oss.str());
					LoggerPtr logger = hierarchy->getLogger(category);
					allLoggers.push_back(logger);
				}
			}
		}

		// Set root level
		root->setLevel(Level::getWarn());

		// Verify all loggers
		for (size_t i = 0; i < allLoggers.size(); ++i)
		{
			assertThresholdConsistent(allLoggers[i]);
			assertThresholdIs(Level::getWarn(), allLoggers[i]);
		}

		// Set levels on some base loggers
		LoggerPtr com = hierarchy->getLogger(LOG4CXX_STR("com"));
		LoggerPtr org = hierarchy->getLogger(LOG4CXX_STR("org"));
		com->setLevel(Level::getInfo());
		org->setLevel(Level::getDebug());

		// Verify all loggers again
		for (size_t i = 0; i < allLoggers.size(); ++i)
		{
			assertThresholdConsistent(allLoggers[i]);
		}

		// Set levels on some mid-level loggers
		LoggerPtr comExample = hierarchy->getLogger(LOG4CXX_STR("com.example"));
		LoggerPtr orgApache = hierarchy->getLogger(LOG4CXX_STR("org.apache"));
		comExample->setLevel(Level::getTrace());
		orgApache->setLevel(Level::getError());

		// Verify all loggers again
		for (size_t i = 0; i < allLoggers.size(); ++i)
		{
			assertThresholdConsistent(allLoggers[i]);
		}

		// Set some to null
		com->setLevel(LevelPtr());

		// Verify all loggers again
		for (size_t i = 0; i < allLoggers.size(); ++i)
		{
			assertThresholdConsistent(allLoggers[i]);
		}

		// Change root level
		root->setLevel(Level::getFatal());

		// Final verification
		for (size_t i = 0; i < allLoggers.size(); ++i)
		{
			assertThresholdConsistent(allLoggers[i]);
		}

		// Verify specific expected values
		LoggerPtr comExampleApp = hierarchy->getLogger(LOG4CXX_STR("com.example.app"));
		assertThresholdConsistent(comExampleApp);
		assertThresholdIs(Level::getTrace(), comExampleApp);

		LoggerPtr orgApacheTest = hierarchy->getLogger(LOG4CXX_STR("org.apache.test"));
		assertThresholdConsistent(orgApacheTest);
		assertThresholdIs(Level::getError(), orgApacheTest);

		LoggerPtr netExampleApp = hierarchy->getLogger(LOG4CXX_STR("net.example.app"));
		assertThresholdConsistent(netExampleApp);
		assertThresholdIs(Level::getFatal(), netExampleApp);
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(LoggerThresholdConsistencyTest);
