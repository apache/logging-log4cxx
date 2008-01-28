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

#if !defined(_LOG4CXX_LOGUNIT_H)
#define _LOG4CXX_LOGUNIT_H

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#define LOGUNIT_TEST_SUITE(x) CPPUNIT_TEST_SUITE(x)
#define LOGUNIT_TEST(x) CPPUNIT_TEST(x)
#define LOGUNIT_TEST_SUITE_END(x) CPPUNIT_TEST_SUITE_END(x)
#define LOGUNIT_ASSERT(x) CPPUNIT_ASSERT(x)
#define LOGUNIT_ASSERT_EQUAL(x, y) CPPUNIT_ASSERT_EQUAL(x, y)
#define LOGUNIT_CLASS(x) class x : public CppUnit::TestFixture
#define LOGUNIT_TEST_SUITE_REGISTRATION(x) CPPUNIT_TEST_SUITE_REGISTRATION(x)
#define LOGUNIT_TEST_SUITE_REGISTRATION_NO_AUTO_RUN(x) CPPUNIT_NS::Test* create ## x () { return x :: suite(); }
#define LOGUNIT_FAIL(msg) CPPUNIT_FAIL(msg)
#define LOGUNIT_TEST_EXCEPTION(t, x) CPPUNIT_TEST_EXCEPTION(t, x)

#endif