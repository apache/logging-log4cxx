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

#include <log4cxx/helpers/charsetencoder.h>
#include "../insertwide.h"
#include <log4cxx/helpers/bytebuffer.h>
#include <apr_xlate.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


class CharsetEncoderTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(CharsetEncoderTestCase);
                CPPUNIT_TEST(encode1);
                CPPUNIT_TEST(encode2);
                CPPUNIT_TEST(encode3);
                CPPUNIT_TEST(encode4);
        CPPUNIT_TEST_SUITE_END();

        enum { BUFSIZE = 256 };

public:


        void encode1() {
          const LogString greeting(LOG4CXX_STR("Hello, World"));
          CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("US-ASCII")));
          char buf[BUFSIZE];
          ByteBuffer out(buf, BUFSIZE);
          LogString::const_iterator iter = greeting.begin();
          log4cxx_status_t stat = enc->encode(greeting, iter, out);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT(iter == greeting.end());

          stat = enc->encode(greeting, iter, out);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT_EQUAL((size_t) 12, out.position());

          out.flip();
          std::string encoded((const char*) out.data(), out.limit());
          CPPUNIT_ASSERT_EQUAL((std::string) "Hello, World", encoded);
          CPPUNIT_ASSERT(iter == greeting.end());
        }

        void encode2() {
          LogString greeting(BUFSIZE - 3, LOG4CXX_STR('A'));
          greeting.append(LOG4CXX_STR("Hello"));

          CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("US-ASCII")));

          char buf[BUFSIZE];
          ByteBuffer out(buf, BUFSIZE);
          LogString::const_iterator iter = greeting.begin();
          log4cxx_status_t stat = enc->encode(greeting, iter, out);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT_EQUAL((size_t) 0, out.remaining());
          CPPUNIT_ASSERT_EQUAL(LOG4CXX_STR('o'), *(iter+1));

          out.flip();
          std::string encoded((char*) out.data(), out.limit());
          out.clear();

          stat = enc->encode(greeting, iter, out);
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          CPPUNIT_ASSERT_EQUAL((size_t) 2, out.position());
          CPPUNIT_ASSERT(iter == greeting.end());

          stat = enc->encode(greeting, iter, out);
          out.flip();
          CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
          encoded.append(out.data(), out.limit());

          std::string manyAs(BUFSIZE - 3, 'A');
          CPPUNIT_ASSERT_EQUAL(manyAs, encoded.substr(0, BUFSIZE - 3));
          CPPUNIT_ASSERT_EQUAL(std::string("Hello"), encoded.substr(BUFSIZE - 3));
        }


        void encode3() {
#if LOG4CXX_LOGCHAR_IS_WCHAR
          //   arbitrary, hopefully meaningless, characters from
          //     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
          const logchar greet[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
          const char greet[] = { 'A',
                                    0xD8, 0x85,
                                    0xD4, 0xB0,
                                    0xE0, 0xA6, 0x86,
                                    0xE4, 0xB8, 0x83,
                                    0xD0, 0x80,
                                    0 };
#endif
          LogString greeting(greet);

          CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("US-ASCII")));

          char buf[BUFSIZE];
          ByteBuffer out(buf, BUFSIZE);

          LogString::const_iterator iter = greeting.begin();
          log4cxx_status_t stat = enc->encode(greeting, iter, out);
          out.flip();
          CPPUNIT_ASSERT_EQUAL(true, CharsetEncoder::isError(stat));
          CPPUNIT_ASSERT_EQUAL((size_t) 1, out.limit());
          CPPUNIT_ASSERT_EQUAL(greet[1], *iter);
          CPPUNIT_ASSERT_EQUAL('A', out.data()[0]);
        }


        void encode4() {
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
          LogString greeting(greet);

          CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("UTF-8")));

          char buf[BUFSIZE];
          ByteBuffer out(buf, BUFSIZE);
          LogString::const_iterator iter = greeting.begin();
          log4cxx_status_t stat = enc->encode(greeting, iter, out);
          CPPUNIT_ASSERT_EQUAL(false, CharsetEncoder::isError(stat));
          stat = enc->encode(greeting, iter, out);
          CPPUNIT_ASSERT_EQUAL(false, CharsetEncoder::isError(stat));

          out.flip();
          CPPUNIT_ASSERT_EQUAL((size_t) 13, out.limit());
          for(int i = 0; i < out.limit(); i++) {
             CPPUNIT_ASSERT_EQUAL((int) utf8_greet[i], (int) out.data()[i]);
          }
          CPPUNIT_ASSERT(iter == greeting.end());
        }



};

CPPUNIT_TEST_SUITE_REGISTRATION(CharsetEncoderTestCase);
