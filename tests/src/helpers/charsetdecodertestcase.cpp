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

#include <log4cxx/helpers/charsetdecoder.h>
#include "../insertwide.h"
#include <log4cxx/helpers/bytebuffer.h>
#include <apr_xlate.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


class CharsetDecoderTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(CharsetDecoderTestCase);
                CPPUNIT_TEST(decode1);
                CPPUNIT_TEST(decode2);
                CPPUNIT_TEST(decode3);
                CPPUNIT_TEST(decode4);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(decode5);
                CPPUNIT_TEST(decode6);
                CPPUNIT_TEST(decode7);
#endif
        CPPUNIT_TEST_SUITE_END();

        enum { BUFSIZE = 256 };

public:


        void decode1() {
          char buf[] = "Hello, World";
          ByteBuffer src(buf, strlen(buf));

          CharsetDecoderPtr dec(CharsetDecoder::getDecoder(LOG4CXX_STR("US-ASCII")));
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
          strcpy(buf + BUFSIZE - 3, "Hello");
          ByteBuffer src(buf, strlen(buf));

          CharsetDecoderPtr dec(CharsetDecoder::getDecoder(LOG4CXX_STR("US-ASCII")));

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


        void decode3() {
          const char buf[] = { 'A', 0xB6, 0 };
          ByteBuffer src((char*) buf, strlen(buf));

          CharsetDecoderPtr dec(CharsetDecoder::getDecoder(LOG4CXX_STR("US-ASCII")));

          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(true, CharsetDecoder::isError(stat));
          CPPUNIT_ASSERT_EQUAL((size_t) 1, src.position());

        }


        void decode4() {
          const char utf8_greet[] = { 'A',
                                    0xD8, 0x85,
                                    0xD4, 0xB0,
                                    0xE0, 0xA6, 0x86,
                                    0xE4, 0xB8, 0x83,
                                    0xD0, 0x80,
                                    0 };
#if LOG4CXX_LOGCHAR_IS_WCHAR
          //   arbitrary, hopefully meaningless, characters from
          //     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
          const logchar greet[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
          const logchar *greet = utf8_greet;
#endif
          ByteBuffer src((char*) utf8_greet, strlen(utf8_greet));

          CharsetDecoderPtr dec(CharsetDecoder::getDecoder(LOG4CXX_STR("UTF-8")));

          LogString greeting;
          log4cxx_status_t stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(false, CharsetDecoder::isError(stat));
          stat = dec->decode(src, greeting);
          CPPUNIT_ASSERT_EQUAL(false, CharsetDecoder::isError(stat));

          CPPUNIT_ASSERT_EQUAL((LogString) greet, greeting);
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
          wcscpy(buf + BUFSIZE - 3, L"Hello");
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


};

CPPUNIT_TEST_SUITE_REGISTRATION(CharsetDecoderTestCase);
