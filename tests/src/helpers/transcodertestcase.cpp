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

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/helpers/transcoder.h>
#include "../insertwide.h"


using namespace log4cxx;
using namespace log4cxx::helpers;


class TranscoderTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(TranscoderTestCase);
                CPPUNIT_TEST(decode1);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(decode2);
#endif
                CPPUNIT_TEST(decode3);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(decode4);
#endif
                CPPUNIT_TEST(decode5);
                CPPUNIT_TEST(decode6);
                CPPUNIT_TEST(decode7);
                CPPUNIT_TEST(decode8);
                CPPUNIT_TEST(decode9);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(encode1);
#endif
                CPPUNIT_TEST(encode2);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(encode3);
#endif
                CPPUNIT_TEST(encode4);
#if LOG4CXX_HAS_WCHAR_T
                CPPUNIT_TEST(encode5);
#endif
                CPPUNIT_TEST(encode6);
        CPPUNIT_TEST_SUITE_END();


public:
        void decode1() {
          const char* greeting = "Hello, World";
          LogString decoded(LOG4CXX_STR("foo\n"));
          Transcoder::decode(greeting, decoded);
          CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\nHello, World"), decoded);
        }

#if LOG4CXX_HAS_WCHAR_T
        void decode2() {
          const wchar_t* greeting = L"Hello, World";
          LogString decoded(LOG4CXX_STR("foo\n"));
          Transcoder::decode(greeting, decoded);
          CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\nHello, World"), decoded);
        }
#endif

        void decode3() {
           const char* nothing = "";
           LogString decoded(LOG4CXX_STR("foo\n"));
           Transcoder::decode(nothing, decoded);
           CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\n"), decoded);
        }

#if LOG4CXX_HAS_WCHAR_T
        void decode4() {
            const wchar_t* nothing = L"";
            LogString decoded(LOG4CXX_STR("foo\n"));
            Transcoder::decode(nothing, decoded);
            CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo\n"), decoded);
        }
#endif

        void decode5() {
            //
            //  copyright symbol on ISO-8859-1, bad sequence in UTF-8
            const char badUTF8[] = { 0xA9, 0 } ;
            LogString decoded(LOG4CXX_STR("foo"));
            Transcoder::decode(badUTF8, decoded);
            CPPUNIT_ASSERT_EQUAL((size_t) 4, decoded.length());
            CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo"), decoded.substr(0, 3));
            if (decoded[3] != (logchar) 0x00A9) {
              CPPUNIT_ASSERT_EQUAL(LOG4CXX_STR('?'), decoded[3]);
            }
        }


        void decode6() {
            //
            //  copyright symbol on ISO-8859-1, bad sequence in UTF-8
            //    Followed by "Hello"
            const char badUTF8[] = { 0xA9, 'H', 'e', 'l', 'l', 'o', 0 } ;
            LogString decoded(LOG4CXX_STR("foo"));
            Transcoder::decode(badUTF8, decoded);
            CPPUNIT_ASSERT_EQUAL((size_t) 9, decoded.length());
            CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("foo"), decoded.substr(0, 3));
            CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Hello"), decoded.substr(4));
            if (decoded[3] != (logchar) 0x00A9) {
              CPPUNIT_ASSERT_EQUAL(LOG4CXX_STR('?'), decoded[3]);
            }
        }

        enum { BUFSIZE = 255 };

        void decode7() {
            //
            //   normal characters striding over a buffer boundary
            //
            std::string longMsg(BUFSIZE - 2, 'A');
            longMsg.append("Hello");
            LogString decoded;
            Transcoder::decode(longMsg, decoded);
            CPPUNIT_ASSERT_EQUAL((size_t) BUFSIZE + 3, decoded.length());
            CPPUNIT_ASSERT_EQUAL(LogString(BUFSIZE -2, LOG4CXX_STR('A')),
                  decoded.substr(0, BUFSIZE - 2));
            CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("Hello"),
                  decoded.substr(BUFSIZE -2 ));
        }

        void decode8() {
            //
            //   Bad UTF-8 striding over a buffer boundary
            //
            std::string longMsg(BUFSIZE - 1, 'A');
            longMsg.append(1, (char) 0xA9);
            LogString decoded;
            Transcoder::decode(longMsg, decoded);
            CPPUNIT_ASSERT_EQUAL((size_t) BUFSIZE, decoded.length());
            CPPUNIT_ASSERT_EQUAL(LogString(BUFSIZE - 1, LOG4CXX_STR('A')),
                  decoded.substr(0, BUFSIZE - 1));
            if (decoded[BUFSIZE - 1] != (logchar) 0x00A9) {
              CPPUNIT_ASSERT_EQUAL(LOG4CXX_STR('?'), decoded[BUFSIZE-1]);
            }
        }


        void decode9() {
            //
            //   Good UTF-8 multibyte sequqnce striding over a buffer boundary
            //
            std::string longMsg(BUFSIZE - 1, 'A');
            longMsg.append(1, (char) 0xC2);
            longMsg.append(1, (char) 0xA9);
            longMsg.append("Hello");
            LogString decoded;
            Transcoder::decode(longMsg, decoded);
            //
            //  starts with a lot of A's
            CPPUNIT_ASSERT_EQUAL(LogString(BUFSIZE - 1, LOG4CXX_STR('A')),
                  decoded.substr(0, BUFSIZE - 1));
            //
            //  ends with Hello
            CPPUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("Hello")),
                  decoded.substr(decoded.length() - 5));
            //
            //  can't say what the middle should be
            //      typically copyright or an accented A + copyright
        }

#if LOG4CXX_HAS_WCHAR_T
        void encode1() {
          const LogString greeting(LOG4CXX_STR("Hello, World"));
          std::wstring encoded;
          Transcoder::encode(greeting, encoded);
          CPPUNIT_ASSERT_EQUAL((std::wstring) L"Hello, World", encoded);
        }
#endif

        void encode2() {
          const LogString greeting(LOG4CXX_STR("Hello, World"));
          std::string encoded;
          Transcoder::encode(greeting, encoded);
          CPPUNIT_ASSERT_EQUAL((std::string) "Hello, World", encoded);
        }

#if LOG4CXX_HAS_WCHAR_T
        void encode3() {
          LogString greeting(BUFSIZE - 3, LOG4CXX_STR('A'));
          greeting.append(LOG4CXX_STR("Hello"));
          std::wstring encoded;
          Transcoder::encode(greeting, encoded);
          std::wstring manyAs(BUFSIZE - 3, L'A');
          CPPUNIT_ASSERT_EQUAL(manyAs, encoded.substr(0, BUFSIZE - 3));
          CPPUNIT_ASSERT_EQUAL(std::wstring(L"Hello"), encoded.substr(BUFSIZE - 3));
        }
#endif

        void encode4() {
          LogString greeting(BUFSIZE - 3, LOG4CXX_STR('A'));
          greeting.append(LOG4CXX_STR("Hello"));
          std::string encoded;
          Transcoder::encode(greeting, encoded);
          std::string manyAs(BUFSIZE - 3, 'A');
          CPPUNIT_ASSERT_EQUAL(manyAs, encoded.substr(0, BUFSIZE - 3));
          CPPUNIT_ASSERT_EQUAL(std::string("Hello"), encoded.substr(BUFSIZE - 3));
        }

#if LOG4CXX_HAS_WCHAR_T
        void encode5() {
          //   arbitrary, hopefully meaningless, characters from
          //     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
          const wchar_t greeting[] = { L'A', 0x0605, 0x0530, 0x984, 0x40E3, 0x400, 0 };
          //
          //  decode to LogString (UTF-16 or UTF-8)
          //
          LogString decoded;
          Transcoder::decode(greeting, 6, decoded);
          //
          //  decode to wstring
          //
          std::wstring encoded;
          Transcoder::encode(decoded, encoded);
          //
          //   should be lossless
          //
          CPPUNIT_ASSERT_EQUAL((std::wstring) greeting, encoded);
        }
#endif

        void encode6() {
#if LOG4CXX_LOGCHAR_IS_WCHAR
          //   arbitrary, hopefully meaningless, characters from
          //     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
          const wchar_t greeting[] = { L'A', 0x0605, 0x0530, 0x984, 0x40E3, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
          const char greeting[] = { 'A',
                                    0xD8, 0x85,
                                    0xD4, 0xB0,
                                    0xE0, 0xCC, 0x84,
                                    0xE8, 0x87, 0x83,
                                    0xD0, 0x80,
                                    0 };
#endif

          //
          //  decode to LogString (UTF-16 or UTF-8)
          //
          LogString decoded;
          Transcoder::decode(greeting, 6, decoded);
          //
          //  decode to wstring
          //
          std::string encoded;
          //
          //   likely 'A\u0605\u0530\u0984\u40E3\u0400'
          //
          Transcoder::encode(decoded, encoded);
        }


};

CPPUNIT_TEST_SUITE_REGISTRATION(TranscoderTestCase);
