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

#include <log4cxx/helpers/stringtokenizer.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>


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
           String src;
           String delim(" ");
           StringTokenizer tokenizer(src, delim);
           try {
             String token(tokenizer.nextToken());
           } catch (NoSuchElementException &ex) {
             return;
           }
           CPPUNIT_ASSERT(false);
        }

        void testHasMoreTokensEmptyString() {
           String src;
           String delim(" ");
           StringTokenizer tokenizer(src, delim);
           CPPUNIT_ASSERT_EQUAL(false, tokenizer.hasMoreTokens());
        }

        void testNextTokenAllDelim() {
           String src("===");
           String delim("=");
           StringTokenizer tokenizer(src, delim);
           try {
             String token(tokenizer.nextToken());
           } catch (NoSuchElementException &ex) {
             return;
           }
           CPPUNIT_ASSERT(false);
        }

        void testHasMoreTokensAllDelim() {
           String src("===");
           String delim("=");
           StringTokenizer tokenizer(src, delim);
           CPPUNIT_ASSERT_EQUAL(false, tokenizer.hasMoreTokens());
        }

        void testBody(const String& src, const String& delim) {
           StringTokenizer tokenizer(src, delim);
           CPPUNIT_ASSERT_EQUAL(true, tokenizer.hasMoreTokens());
           CPPUNIT_ASSERT_EQUAL((String) "log4j", tokenizer.nextToken());
           CPPUNIT_ASSERT_EQUAL(true, tokenizer.hasMoreTokens());
           CPPUNIT_ASSERT_EQUAL((String) "properties", tokenizer.nextToken());
           CPPUNIT_ASSERT_EQUAL(true, tokenizer.hasMoreTokens());
           CPPUNIT_ASSERT_EQUAL((String) "txt", tokenizer.nextToken());
           CPPUNIT_ASSERT_EQUAL(false, tokenizer.hasMoreTokens());
           try {
              String token(tokenizer.nextToken());
           } catch (NoSuchElementException& ex) {
             return;
           }
           CPPUNIT_ASSERT(false);
        }

        void test1() {
          String src("log4j.properties.txt");
          String delim(".");
          testBody(src, delim);
        }

        void test2() {
          String src(".log4j.properties.txt");
          String delim(".");
          testBody(src, delim);
        }

        void test3() {
          String src("log4j.properties.txt.");
          String delim(".");
          testBody(src, delim);
        }

        void test4() {
          String src("log4j..properties....txt");
          String delim(".");
          testBody(src, delim);
        }

        void test5() {
          String src("log4j properties,txt");
          String delim(" ,");
          testBody(src, delim);
        }

        void test6() {
           String src(" log4j properties,txt ");
           String delim(" ,");
           testBody(src, delim);
        }

};

CPPUNIT_TEST_SUITE_REGISTRATION(StringTokenizerTestCase);
