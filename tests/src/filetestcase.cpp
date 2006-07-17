/*
 * Copyright 2004-2005 The Apache Software Foundation.
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
#include <log4cxx/helpers/fileinputstream.h>

#include <log4cxx/helpers/outputstreamwriter.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/inputstreamreader.h>
#include <log4cxx/helpers/fileinputstream.h>

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
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(wcharConstructor);
#endif
                CPPUNIT_TEST(copyConstructor);
                CPPUNIT_TEST(assignment);
                CPPUNIT_TEST(deleteBackslashedFileName);
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

        // check default constructor. read() throws an exception
        // if no file name was given.
        void defaultRead() {
          File defFile;
          Pool pool;
          try {
            InputStreamPtr defInput = new FileInputStream(defFile);
            InputStreamReaderPtr inputReader = new InputStreamReader(defInput);
            LogString contents(inputReader->read(pool));
            CPPUNIT_ASSERT(false);
          } catch(IOException &ex) {
          }
        }


#if LOG4CXX_HAS_WCHAR_T
        void wcharConstructor() {
            File propFile(L"input/patternLayout1.properties");
            Pool pool;
            bool exists = propFile.exists(pool);
            CPPUNIT_ASSERT_EQUAL(true, exists);
       }
#endif

        void copyConstructor() {
            File propFile("input/patternLayout1.properties");
            File copy(propFile);
            Pool pool;
            bool exists = copy.exists(pool);
            CPPUNIT_ASSERT_EQUAL(true, exists);
        }

        void assignment() {
            File propFile("input/patternLayout1.properties");
            File copy = propFile;
            Pool pool;
            bool exists = copy.exists(pool);
            CPPUNIT_ASSERT_EQUAL(true, exists);
        }

        void propertyRead() {
          File propFile("input/patternLayout1.properties");
          Pool pool;
          InputStreamPtr propStream = new FileInputStream(propFile);
          InputStreamReaderPtr propReader = new InputStreamReader(propStream);
          LogString props(propReader->read(pool));
          LogString line1(LOG4CXX_STR("log4j.rootCategory=DEBUG, testAppender"));
          CPPUNIT_ASSERT_EQUAL(line1, props.substr(0, line1.length()));
          LogString tail(LOG4CXX_STR("%-5p - %m%n"));
          CPPUNIT_ASSERT_EQUAL(tail, props.substr(props.length() - tail.length()));
        }

        void propertyExists() {
          File propFile("input/patternLayout1.properties");
          Pool pool;
          bool exists = propFile.exists(pool);
          CPPUNIT_ASSERT_EQUAL(true, exists);
        }

        void fileWrite1() {
          OutputStreamPtr fos =
                      new FileOutputStream(LOG4CXX_STR("output/fileWrite1.txt"));
          OutputStreamWriterPtr osw = new OutputStreamWriter(fos);

          Pool pool;
          LogString greeting(LOG4CXX_STR("Hello, World") LOG4CXX_EOL);
          osw->write(greeting, pool);

          InputStreamPtr is =
                      new FileInputStream(LOG4CXX_STR("output/fileWrite1.txt"));
          InputStreamReaderPtr isr = new InputStreamReader(is);
          LogString reply = isr->read(pool);

          CPPUNIT_ASSERT_EQUAL(greeting, reply);
        }

        /**
         *  Tests conversion of backslash containing file names.
         *  Would cause infinite loop due to bug LOGCXX-105.
         */
        void deleteBackslashedFileName() {
          File file("output\\bogus.txt");
          Pool pool;
          /*bool deleted = */file.deleteFile(pool);
        }
};


CPPUNIT_TEST_SUITE_REGISTRATION(FileTestCase);
