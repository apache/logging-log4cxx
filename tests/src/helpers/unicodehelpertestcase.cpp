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

#if defined(LOG4CXX)
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/helpers/unicodehelper.h>
#include "../testchar.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
 *   Tests for log4cxx::helpers::UnicodeHelper.
 *
 */
class UnicodeHelperTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(UnicodeHelperTestCase);
                CPPUNIT_TEST(testDecodeUTF8_1);
                CPPUNIT_TEST(testDecodeUTF8_2);
                CPPUNIT_TEST(testDecodeUTF8_3);
                CPPUNIT_TEST(testDecodeUTF8_4);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(testDecodeWide_1);
#endif
        CPPUNIT_TEST_SUITE_END();


public:

    void testDecodeUTF8_1() {
        const char* const src = "a";
        const char* iter = src;
        unsigned int sv = UnicodeHelper::decodeUTF8(iter, src + 1);
        CPPUNIT_ASSERT_EQUAL((unsigned int) 0x61, sv);
        CPPUNIT_ASSERT(iter == src + 1);

    }

    void testDecodeUTF8_2() {
        const char src[] = { 0x80};
        const char* iter = src;
        unsigned int sv = UnicodeHelper::decodeUTF8(iter, src + 1);
        CPPUNIT_ASSERT_EQUAL((unsigned int) 0xFFFF, sv);
    }

    void testDecodeUTF8_3() {
        const char src[] = { 0xC2, 0xA9};
        const char* iter = src;
        unsigned int sv = UnicodeHelper::decodeUTF8(iter, src + 1);
        CPPUNIT_ASSERT_EQUAL((unsigned int) 0xFFFF, sv);
    }

    void testDecodeUTF8_4() {
        const char src[] = { 0xC2, 0xA9};
        const char* iter = src;
        unsigned int sv = UnicodeHelper::decodeUTF8(iter, src + 2);
        CPPUNIT_ASSERT_EQUAL((unsigned int) 0xA9, sv);
    }

#if LOG4CXX_HAS_WCHAR_T
    void testDecodeWide_1() {
        const wchar_t* const src = L"a";
        const wchar_t* iter = src;
        unsigned int sv = UnicodeHelper::decodeWide(iter, src + 1);
        CPPUNIT_ASSERT_EQUAL((unsigned int) 0x61, sv);
        CPPUNIT_ASSERT(iter == src + 1);
    }
#endif

};

CPPUNIT_TEST_SUITE_REGISTRATION(UnicodeHelperTestCase);

#endif
