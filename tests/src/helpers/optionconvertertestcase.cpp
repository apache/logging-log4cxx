/*
 * Copyright 2003,2005 The Apache Software Foundation.
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
#include <apr_pools.h>
#include <apr_file_io.h>
#include <apr_user.h>


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
      CPPUNIT_TEST(testTmpDir);
#if APR_HAS_USER
      CPPUNIT_TEST(testUserHome);
      CPPUNIT_TEST(testUserName);
#endif
      CPPUNIT_TEST(testUserDir);
   CPPUNIT_TEST_SUITE_END();

   Properties props;
   Properties nullProperties;

public:
   void setUp()
   {
   }

   void tearDown()
   {
   }

   /**
   * Checks that environment variables were properly set
   * before invoking tests.  ::putenv not reliable.
   */
   void envCheck() {
     const char* toto = ::getenv("TOTO");
     CPPUNIT_ASSERT(toto != NULL);
     CPPUNIT_ASSERT_EQUAL(std::string("wonderful"), (std::string) toto);
     const char* key1 = ::getenv("key1");
     CPPUNIT_ASSERT(key1 != NULL);
     CPPUNIT_ASSERT_EQUAL(std::string("value1"), (std::string) key1);
     const char* key2 = ::getenv("key2");
     CPPUNIT_ASSERT(key2 != NULL);
     CPPUNIT_ASSERT_EQUAL(std::string("value2"), (std::string) key2);
   }

   void varSubstTest1()
   {
      envCheck();
      LogString r(OptionConverter::substVars(LOG4CXX_STR("hello world."), nullProperties));
      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("hello world."), r);

      r = OptionConverter::substVars(LOG4CXX_STR("hello ${TOTO} world."), nullProperties);

      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("hello wonderful world."), r);
   }


   void varSubstTest2()
   {
     envCheck();
      LogString r(OptionConverter::substVars(LOG4CXX_STR("Test2 ${key1} mid ${key2} end."),
         nullProperties));
      CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Test2 value1 mid value2 end."), r);
   }


   void varSubstTest3()
   {
     envCheck();
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

    void testTmpDir()
    {
       LogString actual(OptionConverter::substVars(
          LOG4CXX_STR("${java.io.tmpdir}"), nullProperties));
       apr_pool_t* p;
       apr_status_t stat = apr_pool_create(&p, NULL);
       CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
       const char* tmpdir = NULL;
       stat = apr_temp_dir_get(&tmpdir, p);
       CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
       LogString expected;
       Transcoder::decode(tmpdir, strlen(tmpdir), expected);
       apr_pool_destroy(p);

       CPPUNIT_ASSERT_EQUAL(expected, actual);
    }

#if APR_HAS_USER
    void testUserHome() {
      LogString actual(OptionConverter::substVars(
         LOG4CXX_STR("${user.home}"), nullProperties));
      apr_pool_t* p;
      apr_status_t stat = apr_pool_create(&p, NULL);
      CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

      apr_uid_t userid;
      apr_gid_t groupid;
      stat = apr_uid_current(&userid, &groupid, p);
      CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

      char* username = NULL;
      stat = apr_uid_name_get(&username, userid, p);
      CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

      char* dirname = NULL;
      stat = apr_uid_homepath_get(&dirname, username, p);

      LogString expected;
      Transcoder::decode(dirname, strlen(dirname), expected);
      apr_pool_destroy(p);

      CPPUNIT_ASSERT_EQUAL(expected, actual);
    }

    void testUserName() {
       LogString actual(OptionConverter::substVars(
           LOG4CXX_STR("${user.name}"), nullProperties));
       apr_pool_t* p;
       apr_status_t stat = apr_pool_create(&p, NULL);
       CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

       apr_uid_t userid;
       apr_gid_t groupid;
       stat = apr_uid_current(&userid, &groupid, p);
       CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

       char* username = NULL;
       stat = apr_uid_name_get(&username, userid, p);
       CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

       LogString expected;
       Transcoder::decode(username, strlen(username), expected);
       apr_pool_destroy(p);

       CPPUNIT_ASSERT_EQUAL(expected, actual);
   }
#endif

    void testUserDir() {
      LogString actual(OptionConverter::substVars(
          LOG4CXX_STR("${user.dir}"), nullProperties));
      apr_pool_t* p;
      apr_status_t stat = apr_pool_create(&p, NULL);
      CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

      char* dirname = NULL;
      stat = apr_filepath_get(&dirname, APR_FILEPATH_NATIVE, p);
      CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

      LogString expected;
      Transcoder::decode(dirname, strlen(dirname), expected);
      apr_pool_destroy(p);

      CPPUNIT_ASSERT_EQUAL(expected, actual);
    }
};

CPPUNIT_TEST_SUITE_REGISTRATION(OptionConverterTestCase);
