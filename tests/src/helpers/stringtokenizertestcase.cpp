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
#include <log4cxx/logstring.h>
#include <log4cxx/helpers/stringtokenizer.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include "../insertwide.h"


using namespace log4cxx;
using namespace log4cxx::helpers;

class StringTokenizerTestCase : public CppUnit::TestFixture
{
   CPPUNIT_TEST_SUITE(StringTokenizerTestCase);
      CPPUNIT_TEST(testNextTokenEmptyString);
                CPPUNIT_TEST(testHasMoreTokensEmptyString);
                CPPUNIT_TEST(testNextTokenAllDelim);
                CPPUNIT_TEST(testHasMoreTokensAllDelim);
                CPPUNIT_TEST(test1);
                CPPUNIT_TEST(test2);
                CPPUNIT_TEST(test3);
                CPPUNIT_TEST(test4);
                CPPUNIT_TEST(test5);
                CPPUNIT_TEST(test6);
   CPPUNIT_TEST_SUITE_END();

public:
        void testNextTokenEmptyString() {
           LogString src;
           LogString delim(LOG4CXX_STR(" "));
           StringTokenizer tokenizer(src, delim);
           try {
             LogString token(tokenizer.nextToken());
           } catch (NoSuchElementException &ex) {
             return;
           }
           CPPUNIT_ASSERT(false);
        }

        void testHasMoreTokensEmptyString() {
           LogString src;
           LogString delim(LOG4CXX_STR(" "));
           StringTokenizer tokenizer(src, delim);
           CPPUNIT_ASSERT_EQUAL(false, tokenizer.hasMoreTokens());
        }

        void testNextTokenAllDelim() {
           LogString src(LOG4CXX_STR("==="));
           LogString delim(LOG4CXX_STR("="));
           StringTokenizer tokenizer(src, delim);
           try {
             LogString token(tokenizer.nextToken());
           } catch (NoSuchElementException &ex) {
             return;
           }
           CPPUNIT_ASSERT(false);
        }

        void testHasMoreTokensAllDelim() {
           LogString src(LOG4CXX_STR("==="));
           LogString delim(LOG4CXX_STR("="));
           StringTokenizer tokenizer(src, delim);
           CPPUNIT_ASSERT_EQUAL(false, tokenizer.hasMoreTokens());
        }

        void testBody(const LogString& src, const LogString& delim) {
           StringTokenizer tokenizer(src, delim);
           CPPUNIT_ASSERT_EQUAL(true, tokenizer.hasMoreTokens());
           CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("log4j"), tokenizer.nextToken());
           CPPUNIT_ASSERT_EQUAL(true, tokenizer.hasMoreTokens());
           CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("properties"), tokenizer.nextToken());
           CPPUNIT_ASSERT_EQUAL(true, tokenizer.hasMoreTokens());
           CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("txt"), tokenizer.nextToken());
           CPPUNIT_ASSERT_EQUAL(false, tokenizer.hasMoreTokens());
           try {
              LogString token(tokenizer.nextToken());
           } catch (NoSuchElementException& ex) {
             return;
           }
           CPPUNIT_ASSERT(false);
        }

        void test1() {
          LogString src(LOG4CXX_STR("log4j.properties.txt"));
          LogString delim(LOG4CXX_STR("."));
          testBody(src, delim);
        }

        void test2() {
          LogString src(LOG4CXX_STR(".log4j.properties.txt"));
          LogString delim(LOG4CXX_STR("."));
          testBody(src, delim);
        }

        void test3() {
          LogString src(LOG4CXX_STR("log4j.properties.txt."));
          LogString delim(LOG4CXX_STR("."));
          testBody(src, delim);
        }

        void test4() {
          LogString src(LOG4CXX_STR("log4j..properties....txt"));
          LogString delim(LOG4CXX_STR("."));
          testBody(src, delim);
        }

        void test5() {
          LogString src(LOG4CXX_STR("log4j properties,txt"));
          LogString delim(LOG4CXX_STR(" ,"));
          testBody(src, delim);
        }

        void test6() {
           LogString src(LOG4CXX_STR(" log4j properties,txt "));
           LogString delim(LOG4CXX_STR(" ,"));
           testBody(src, delim);
        }

};

CPPUNIT_TEST_SUITE_REGISTRATION(StringTokenizerTestCase);
