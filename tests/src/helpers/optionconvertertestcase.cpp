/*
 * Copyright 2003,2004 The Apache Software Foundation.
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

#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/helpers/transcoder.h>
#include "../testchar.h"
#include "../insertwide.h"
#include <stdlib.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

#define MAX 1000

class OptionConverterTestCase : public CppUnit::TestFixture
{
   CPPUNIT_TEST_SUITE(OptionConverterTestCase);
      CPPUNIT_TEST(varSubstTest1);
      CPPUNIT_TEST(varSubstTest2);
      CPPUNIT_TEST(varSubstTest3);
      CPPUNIT_TEST(varSubstTest4);
      CPPUNIT_TEST(varSubstTest5);
   CPPUNIT_TEST_SUITE_END();

   Properties props;
   Properties nullProperties;

public:
   void setUp()
   {
      ::putenv("TOTO=wonderful");
      ::putenv("key1=value1");
      ::putenv("key2=value2");
   }

   void tearDown()
   {
   }

   void varSubstTest1()
   {
      LogString r(OptionConverter::substVars(LOG4CXX_STR("hello world."), nullProperties));
      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("hello world."), r);

      r = OptionConverter::substVars(LOG4CXX_STR("hello ${TOTO} world."), nullProperties);

      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("hello wonderful world."), r);
   }


   void varSubstTest2()
   {
      LogString r(OptionConverter::substVars(LOG4CXX_STR("Test2 ${key1} mid ${key2} end."),
         nullProperties));
      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Test2 value1 mid value2 end."), r);
   }


   void varSubstTest3()
   {
      LogString r(OptionConverter::substVars(
         LOG4CXX_STR("Test3 ${unset} mid ${key1} end."), nullProperties));
      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Test3  mid value1 end."), r);
   }


   void varSubstTest4()
   {
      LogString res;
      LogString val(LOG4CXX_STR("Test4 ${incomplete "));
      try
      {
         res = OptionConverter::substVars(val, nullProperties);
      }
      catch(IllegalArgumentException& e)
      {
         std::string witness("\"Test4 ${incomplete \" has no closing brace. Opening brace at position 6.");
         CPPUNIT_ASSERT_EQUAL(witness, (std::string) e.what());
      }
   }


   void varSubstTest5()
   {
      Properties props;
      props.setProperty(LOG4CXX_STR("p1"), LOG4CXX_STR("x1"));
      props.setProperty(LOG4CXX_STR("p2"), LOG4CXX_STR("${p1}"));
      LogString res = OptionConverter::substVars(LOG4CXX_STR("${p2}"), props);
      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("x1"), res);
   }

        private:
};

CPPUNIT_TEST_SUITE_REGISTRATION(OptionConverterTestCase);
