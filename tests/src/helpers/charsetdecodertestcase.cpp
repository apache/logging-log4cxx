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

#include <log4cxx/helpers/charsetdecoder.h>
#include "../insertwide.h"
#include <log4cxx/helpers/bytebuffer.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


#define APR_SUCCESS ((log4cxx_status_t) 0)



class CharsetDecoderTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(CharsetDecoderTestCase);
                CPPUNIT_TEST(decode1);
                CPPUNIT_TEST(decode2);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(decode5);
                CPPUNIT_TEST(decode6);
                CPPUNIT_TEST(decode7);
#endif
                CPPUNIT_TEST(decode8);
        CPPUNIT_TEST_SUITE_END();

        enum { BUFSIZE = 256 };

public:


        void decode1() {
          char buf[] = "Hello, World";
          ByteBuffer src(buf, strlen(buf));

          CharsetDecoderPtr dec(CharsetDecoder::getDefaultDecoder());
          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

          stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT_EQUAL((size_t) 12, src.position());

          CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Hello, World"), greeting);
        }

        void decode2() {
          char buf[BUFSIZE + 6];
          memset(buf, 'A', BUFSIZE);
          buf[BUFSIZE - 3] = 0;
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_SECURE_LIB__)
          strcat_s(buf, sizeof buf, "Hello");
#else
          strcat(buf, "Hello");
#endif
          ByteBuffer src(buf, strlen(buf));

          CharsetDecoderPtr dec(CharsetDecoder::getDefaultDecoder());

          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT_EQUAL((size_t) 0, src.remaining());


          stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

          LogString manyAs(BUFSIZE - 3, LOG4CXX_STR('A'));
          CPPUNIT_ASSERT_EQUAL(manyAs, greeting.substr(0, BUFSIZE - 3));
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Hello")), greeting.substr(BUFSIZE - 3));
        }



#if LOG4CXX_HAS_WCHAR_T
        void decode5() {
          wchar_t buf[] = L"Hello, World";
          ByteBuffer src((char*) buf, wcslen(buf) * sizeof(wchar_t));

          CharsetDecoderPtr dec(CharsetDecoder::getWideDecoder());

          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

          stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

          CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Hello, World"), greeting);
        }

        void decode6() {
          wchar_t buf[BUFSIZE + 6];
          for(int i = 0; i < BUFSIZE; i++) {
            buf[i] = L'A';
          }
          buf[BUFSIZE - 3] = 0;
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_SECURE_LIB__)
          wcscat_s(buf, (sizeof buf)/sizeof(wchar_t), L"Hello");
#else
          wcscat(buf, L"Hello");
#endif
          ByteBuffer src((char*) buf, wcslen(buf) * sizeof(wchar_t));

          CharsetDecoderPtr dec(CharsetDecoder::getWideDecoder());

          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT_EQUAL((size_t) 0, src.remaining());


          stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

          LogString manyAs(BUFSIZE - 3, LOG4CXX_STR('A'));
          CPPUNIT_ASSERT_EQUAL(manyAs, greeting.substr(0, BUFSIZE - 3));
          CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Hello")), greeting.substr(BUFSIZE - 3));
        }

        void decode7() {
          //   arbitrary, hopefully meaningless, characters from
          //     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
          const wchar_t wide_greet[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x400, 0 };
#if LOG4CXX_LOGCHAR_IS_WCHAR
          const logchar* greet = wide_greet;
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
          const logchar greet[] = { 'A',
                                    0xD8, 0x85,
                                    0xD4, 0xB0,
                                    0xE0, 0xA6, 0x86,
                                    0xE4, 0xB8, 0x83,
                                    0xD0, 0x80,
                                    0 };

#endif
          ByteBuffer src((char*) wide_greet, wcslen(wide_greet) * sizeof(wchar_t));

          CharsetDecoderPtr dec(CharsetDecoder::getWideDecoder());

          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(false, CharsetDecoder::isError(stat));
          stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(false, CharsetDecoder::isError(stat));

          CPPUNIT_ASSERT_EQUAL((LogString) greet, greeting);
        }

#endif

        void decode8() {
          char buf[] = { 'H', 'e', 'l', 'l', 'o', ',', 0, 'W', 'o', 'r', 'l', 'd'};
          ByteBuffer src(buf, 12);

          CharsetDecoderPtr dec(CharsetDecoder::getDefaultDecoder());
          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

          stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT_EQUAL((size_t) 12, src.position());

          LogString expected(LOG4CXX_STR("Hello,\0World"), 12);
          CPPUNIT_ASSERT_EQUAL(expected, greeting);
        }



};

CPPUNIT_TEST_SUITE_REGISTRATION(CharsetDecoderTestCase);
