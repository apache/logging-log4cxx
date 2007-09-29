
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

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/level.h>
#include "testchar.h"


using namespace log4cxx;

class LevelTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(LevelTestCase);
                CPPUNIT_TEST(testToLevelFatal);
                CPPUNIT_TEST(testTraceInt);
                CPPUNIT_TEST(testTrace);
                CPPUNIT_TEST(testIntToTrace);
                CPPUNIT_TEST(testStringToTrace);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(testWideStringToTrace);
#endif                
        CPPUNIT_TEST_SUITE_END();

public:
        void testToLevelFatal()
        {
                LevelPtr level(Level::toLevel(LOG4CXX_TEST_STR("fATal")));
                CPPUNIT_ASSERT_EQUAL((int) Level::FATAL_INT, level->toInt());
        }
        
    /**
     * Tests Level::TRACE_INT.
     */
  void testTraceInt() {
      CPPUNIT_ASSERT_EQUAL(5000, (int) Level::TRACE_INT);
  }

    /**
     * Tests Level.TRACE.
     */
  void testTrace() {
      CPPUNIT_ASSERT(Level::getTrace()->toString() == LOG4CXX_STR("TRACE"));
      CPPUNIT_ASSERT_EQUAL(5000, Level::getTrace()->toInt());
      CPPUNIT_ASSERT_EQUAL(7, Level::getTrace()->getSyslogEquivalent());
  }

    /**
     * Tests Level.toLevel(Level.TRACE_INT).
     */
  void testIntToTrace() {
      LevelPtr trace(Level::toLevel(5000));
      CPPUNIT_ASSERT(trace->toString() == LOG4CXX_STR("TRACE"));
  }

    /**
     * Tests Level.toLevel("TRACE");
     */
  void testStringToTrace() {
        LevelPtr trace(Level::toLevel("TRACE"));
		CPPUNIT_ASSERT(trace->toString() == LOG4CXX_STR("TRACE"));
  }

#if LOG4CXX_HAS_WCHAR_T
    /**
     * Tests Level.toLevel(L"TRACE");
     */
  void testWideStringToTrace() {
        LevelPtr trace(Level::toLevel(L"TRACE"));
        CPPUNIT_ASSERT(trace->toString() == LOG4CXX_STR("TRACE"));
  }
#endif  
        

};

CPPUNIT_TEST_SUITE_REGISTRATION(LevelTestCase);
