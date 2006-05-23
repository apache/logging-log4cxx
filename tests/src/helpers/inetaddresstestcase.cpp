/*
 * Copyright 2005 The Apache Software Foundation.
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
#include <log4cxx/helpers/inetaddress.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


class InetAddressTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(InetAddressTestCase);
                CPPUNIT_TEST(testGetLocalHost);
                CPPUNIT_TEST(testByNameLocal);
                CPPUNIT_TEST(testAllByNameLocal);
                CPPUNIT_TEST_EXCEPTION(testUnknownHost, UnknownHostException);
//                CPPUNIT_TEST(testByNameRemote);
        CPPUNIT_TEST_SUITE_END();

public:
        /**
         * Tests the InetAddress::getLocalHost() method.
         */
        void testGetLocalHost() {
           InetAddressPtr addr = InetAddress::getLocalHost();

           CPPUNIT_ASSERT(addr->getHostAddress() == LOG4CXX_STR("127.0.0.1"));
           CPPUNIT_ASSERT(!addr->getHostName().empty());
        }

        /**
         * Tests the InetAddress::getByName() method with the
         * "localhost" host name.
         */
        void testByNameLocal() {
           InetAddressPtr addr = InetAddress::getByName(LOG4CXX_STR("localhost"));

           CPPUNIT_ASSERT(addr->getHostAddress() == LOG4CXX_STR("127.0.0.1"));
           CPPUNIT_ASSERT(!addr->getHostName().empty());
        }

        /**
         * Tests the InetAddress::getAllByName() method with the
         * "localhost" host name.
         */
        void testAllByNameLocal() {
           std::vector<InetAddressPtr> addr = InetAddress::getAllByName(LOG4CXX_STR("localhost"));

           CPPUNIT_ASSERT(addr.size() > 0);
        }

        /**
         * Tests the UnknownHostException.
         */
        void testUnknownHost() {
           InetAddressPtr addr = InetAddress::getByName(LOG4CXX_STR("unknown.host.local"));
        }

        /**
         * Tests resolving a remote host name.
         * This test is usually disabled in the test suite because it
         * probably produces volatile data.
         */
        void testByNameRemote() {
            InetAddressPtr addr = InetAddress::getByName(LOG4CXX_STR("www.apache.org"));

            CPPUNIT_ASSERT(addr->getHostAddress() == LOG4CXX_STR("209.237.227.195"));
            CPPUNIT_ASSERT(addr->getHostName() == LOG4CXX_STR("minotaur-2.apache.org"));
        }
};


CPPUNIT_TEST_SUITE_REGISTRATION(InetAddressTestCase);

