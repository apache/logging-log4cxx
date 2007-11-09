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
#include <log4cxx/helpers/messagebuffer.h>
#include <log4cxx/helpers/messagebuffer.h>
#include <iomanip>

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
 *  Test MessageBuffer.
 */
class MessageBufferTest : public CppUnit::TestFixture
{
   CPPUNIT_TEST_SUITE(MessageBufferTest);
      CPPUNIT_TEST(testInsertChar);
      CPPUNIT_TEST(testInsertCStr);
      CPPUNIT_TEST(testInsertString);
      CPPUNIT_TEST(testInsertNull);
      CPPUNIT_TEST(testInsertInt);
      CPPUNIT_TEST(testInsertManipulator);
   CPPUNIT_TEST_SUITE_END();


public:
    void testInsertChar() {
        MessageBuffer buf;
        std::string greeting("Hello, World");
        CharMessageBuffer& retval = buf << "Hello, Worl" << 'd';
        CPPUNIT_ASSERT_EQUAL(greeting, buf.str(retval)); 
        CPPUNIT_ASSERT_EQUAL(false, buf.hasStream());
    }

    void testInsertCStr() {
        MessageBuffer buf;
        std::string greeting("Hello, World");
        CharMessageBuffer& retval = buf << "Hello" << ", World";
        CPPUNIT_ASSERT_EQUAL(greeting, buf.str(retval)); 
        CPPUNIT_ASSERT_EQUAL(false, buf.hasStream());
    }

    void testInsertString() {
        MessageBuffer buf;
        std::string greeting("Hello, World");
        CharMessageBuffer& retval = buf << std::string("Hello") << std::string(", World");
        CPPUNIT_ASSERT_EQUAL(greeting, buf.str(retval)); 
        CPPUNIT_ASSERT_EQUAL(false, buf.hasStream());
    }
    
    void testInsertNull() {
        MessageBuffer buf;
        std::string greeting("Hello, null");
        CharMessageBuffer& retval = buf << "Hello, " << (const char*) 0;
        CPPUNIT_ASSERT_EQUAL(greeting, buf.str(retval)); 
        CPPUNIT_ASSERT_EQUAL(false, buf.hasStream());
    }
    
    void testInsertInt() {
        MessageBuffer buf;
        std::string greeting("Hello, 5");
        std::ostream& retval = buf << "Hello, " << 5;
        CPPUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
        CPPUNIT_ASSERT_EQUAL(true, buf.hasStream());
    }
        
    void testInsertManipulator() {
        MessageBuffer buf;
        std::string greeting("pi=3.142");
        std::ostream& retval = buf << "pi=" << std::setprecision(4) << 3.1415926;
        CPPUNIT_ASSERT_EQUAL(greeting, buf.str(retval));
        CPPUNIT_ASSERT_EQUAL(true, buf.hasStream());
    }


};

CPPUNIT_TEST_SUITE_REGISTRATION(MessageBufferTest);

