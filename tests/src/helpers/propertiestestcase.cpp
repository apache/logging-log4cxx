/*
 * Copyright 2005 The Apache Software Foundation.
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

#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/helpers/properties.h>
#include "../insertwide.h"

using namespace log4cxx;
using namespace log4cxx::helpers;


class PropertiesTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(PropertiesTestCase);
                CPPUNIT_TEST(testLoad1);
        CPPUNIT_TEST_SUITE_END();

public:
        void testLoad1() {
          //
          //    line from patternLayout1.properties
          LogString line(LOG4CXX_STR("log4j.appender.testAppender.layout.ConversionPattern=%-5p - %m%n"));
          Properties properties;
          properties.load(line);
          LogString pattern(properties.getProperty(LOG4CXX_STR("log4j.appender.testAppender.layout.ConversionPattern")));
          CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("%-5p - %m%n"), pattern);
        }
};


CPPUNIT_TEST_SUITE_REGISTRATION(PropertiesTestCase);
