
/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

using namespace log4cxx;

class LevelTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(LevelTestCase);
                CPPUNIT_TEST(testToLevelFatal);
        CPPUNIT_TEST_SUITE_END();

public:
        void testToLevelFatal()
        {
                LevelPtr level(Level::toLevel(L"fATal"));
                CPPUNIT_ASSERT_EQUAL((int) Level::FATAL_INT, level->toInt());
        }

};

CPPUNIT_TEST_SUITE_REGISTRATION(LevelTestCase);
