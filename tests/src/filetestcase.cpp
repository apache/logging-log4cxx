/*
 * Copyright 2004 The Apache Software Foundation.
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
#include <log4cxx/file.h>
#include "insertwide.h"
#include <log4cxx/helpers/pool.h>
#include <apr_errno.h>
#include <log4cxx/helpers/exception.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


class FileTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(FileTestCase);
                CPPUNIT_TEST(defaultConstructor);
                CPPUNIT_TEST(defaultExists);
                CPPUNIT_TEST(defaultRead);
                CPPUNIT_TEST(propertyRead);
                CPPUNIT_TEST(propertyExists);
                CPPUNIT_TEST(fileWrite1);
                CPPUNIT_TEST(wcharConstructor);
                CPPUNIT_TEST(copyConstructor);
                CPPUNIT_TEST(assignment);
        CPPUNIT_TEST_SUITE_END();

public:
        void defaultConstructor() {
          File defFile;
          CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR(""), defFile.getName());
        }



        void defaultExists() {
          File defFile;
          Pool pool;
          bool exists = defFile.exists(pool);
          CPPUNIT_ASSERT_EQUAL(false, exists);
        }


        void defaultRead() {
          File defFile;
          Pool pool;
          try {
            LogString contents(defFile.read(pool));
            CPPUNIT_ASSERT(false);
          } catch(IOException &ex) {
          }
        }


        void defaultWrite() {
          File defFile;
          Pool pool;
          LogString greeting(LOG4CXX_STR("Hello, World"));
          apr_status_t stat = defFile.write(greeting, pool);
          CPPUNIT_ASSERT(stat != APR_SUCCESS);
        }


        void wcharConstructor() {
            File propFile(L"input/patternLayout1.properties");
            Pool pool;
            bool exists = propFile.exists(pool);
            CPPUNIT_ASSERT_EQUAL(true, exists);
       }


        void copyConstructor() {
            File propFile(L"input/patternLayout1.properties");
            File copy(propFile);
            Pool pool;
            bool exists = copy.exists(pool);
            CPPUNIT_ASSERT_EQUAL(true, exists);
        }

        void assignment() {
            File propFile(L"input/patternLayout1.properties");
            File copy = propFile;
            Pool pool;
            bool exists = copy.exists(pool);
            CPPUNIT_ASSERT_EQUAL(true, exists);
        }

        void propertyRead() {
          File propFile("input/patternLayout1.properties");
          Pool pool;
          LogString props(propFile.read(pool));
          LogString line1(LOG4CXX_STR("log4j.rootCategory=DEBUG, testAppender\n"));
          CPPUNIT_ASSERT_EQUAL(line1, props.substr(0, line1.length()));
        }

        void propertyExists() {
          File propFile("input/patternLayout1.properties");
          Pool pool;
          bool exists = propFile.exists(pool);
          CPPUNIT_ASSERT_EQUAL(true, exists);
        }


        void fileWrite1() {
          File outFile("output/fileWrite1.txt");
          Pool pool;
          LogString greeting(LOG4CXX_STR("Hello, World\n"));
          apr_status_t stat = outFile.write(greeting, pool);
          CPPUNIT_ASSERT_EQUAL(0, stat);

          LogString reply(outFile.read(pool));
          CPPUNIT_ASSERT_EQUAL(greeting, reply);
        }
};


CPPUNIT_TEST_SUITE_REGISTRATION(FileTestCase);
