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

#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/file.h>


using namespace log4cxx;
using namespace log4cxx::helpers;


class FileTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(FileTestCase);
		CPPUNIT_TEST(defaultConstructor);
		CPPUNIT_TEST(defaultExists);
		CPPUNIT_TEST(defaultRead);
        CPPUNIT_TEST(propertyRead);
        CPPUNIT_TEST(fileWrite1);
	CPPUNIT_TEST_SUITE_END();

public:
	void defaultConstructor()
	{
        File defFile;
        CPPUNIT_ASSERT_EQUAL(std::string(), defFile.getMBCSName());
        CPPUNIT_ASSERT_EQUAL(LogString(), defFile.getName());
	}

	void defaultExists()
	{
        File defFile;
        CPPUNIT_ASSERT_EQUAL(false, defFile.exists());
	}


	void defaultRead()
	{
        File defFile;
        Pool pool;
        CPPUNIT_ASSERT_EQUAL(LogString, defFile.read(pool));
	}


	void defaultWrite()
	{
        File defFile;
        Pool pool;
        LogString greeting("Hello, World");
        CPPUNIT_ASSERT(defFile.write(greeting, pool) != APR_SUCCESS);
	}

    void propertyRead() {
        File propFile("input//patternLayout1.properties");
        Pool pool;
        LogString props(propFile.read(pool));
        LogString line1(LOG4CXX_STR("log4j.rootCategory=DEBUG, testAppender\n"));
        CPPUNIT_ASSERT_EQUAL(line1, props.substr(0, line1.length());
    }


    void fileWrite1() {
        File outFile("output//fileWrite1.txt");
        Pool pool;
        LogString greeting(LOG4CXX_STR("Hello, World\n"));
        apr_status_t stat = outFile.write(greeting, pool);
        CPPUNIT_ASSERT_EQUAL(0, stat);

        LogString reply(outFile.read(pool));
        CPPUNIT_ASSERT_EQUAL(greeting, reply);
    }

};


CPPUNIT_TEST_SUITE_REGISTRATION(FileTestCase);
