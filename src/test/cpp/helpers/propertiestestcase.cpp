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

#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/fileinputstream.h>
#include "../insertwide.h"
#include "../logunit.h"

using namespace log4cxx;
using namespace log4cxx::helpers;


LOGUNIT_CLASS(PropertiesTestCase)
{
	LOGUNIT_TEST_SUITE(PropertiesTestCase);
	LOGUNIT_TEST(testLoad1);
	LOGUNIT_TEST(testTab1);
	LOGUNIT_TEST(testTab2);
	LOGUNIT_TEST(testTab3);
	LOGUNIT_TEST(testTab4);
	LOGUNIT_TEST(testTab5);
	LOGUNIT_TEST(testTab6);
	LOGUNIT_TEST(testTab7);
	LOGUNIT_TEST(testCRLF1);
	LOGUNIT_TEST(testEscT1);
	LOGUNIT_TEST(testEscT2);
	LOGUNIT_TEST(testEscN1);
	LOGUNIT_TEST(testEscN2);
	LOGUNIT_TEST(testEscR1);
	LOGUNIT_TEST(testEscR2);
	LOGUNIT_TEST_SUITE_END();

public:
	void testLoad1()
	{
		//
		//    read patternLayout1.properties
		FileInputStreamPtr propFile =
			new FileInputStream(LOG4CXX_STR("input/patternLayout1.properties"));
		Properties properties;
		properties.load(propFile);
		LogString pattern(properties.getProperty(LOG4CXX_STR("log4j.appender.testAppender.layout.ConversionPattern")));
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("%-5p - %m%n"), pattern);
	}

	/**
	 *  Test tab as separator between key and value, see LOGCXX-291.
	*/
	void testTab1()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.tab1")));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("tab delimited")), actual);
	}

	/**
	 *  Test tab as whitespace before key, see LOGCXX-291.
	*/
	void testTab2()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.tab2")));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("tab before key")), actual);
	}

	/**
	 *  Test tab as escaped within key, see LOGCXX-291.
	*/
	void testTab3()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString key(LOG4CXX_STR("propertiestestcase.tab3"));
		key.append(1, 0x09);
		LogString actual(properties.getProperty(key));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("key contains tab")), actual);
	}

	/**
	 *  Test tab after delimitor, see LOGCXX-291.
	*/
	void testTab4()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.tab4")));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("tab after equals")), actual);
	}

	/**
	 *  Test tab after continuation in key, see LOGCXX-291.
	*/
	void testTab5()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.tab5")));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("tab after continue")), actual);
	}

	/**
	 *  Test tab escaped in value, see LOGCXX-291.
	*/
	void testTab6()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.tab6")));
		LogString expected(1, 0x09);
		expected.append(LOG4CXX_STR(" in value"));
		LOGUNIT_ASSERT_EQUAL(expected, actual);
	}

	/**
	 *  Test tab in value continuation, see LOGCXX-291.
	*/
	void testTab7()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.tab7")));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("continuedvalue")), actual);
	}

	/**
	 *  Test tab in value continuation, see LOGCXX-292.
	*/
	void testCRLF1()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.crlf1")));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("continuedvalue")), actual);
	}

	/**
	 *  Test tab as escaped within key, see LOGCXX-293.
	*/
	void testEscT1()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString key(LOG4CXX_STR("propertiestestcase.esct1"));
		key.append(1, 0x09);
		LogString actual(properties.getProperty(key));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("key contains tab")), actual);
	}



	/**
	 *  Test tab escaped in value, see LOGCXX-293.
	*/
	void testEscT2()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.esct2")));
		LogString expected(1, 0x09);
		expected.append(LOG4CXX_STR(" in value"));
		LOGUNIT_ASSERT_EQUAL(expected, actual);
	}

	/**
	 *  Test \n within key, see LOGCXX-293.
	*/
	void testEscN1()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;;
		properties.load(propFile);
		LogString key(LOG4CXX_STR("propertiestestcase.escn1"));
		key.append(1, 0x0A);
		LogString actual(properties.getProperty(key));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("key contains lf")), actual);
	}



	/**
	 *  Test \n in value, see LOGCXX-293.
	*/
	void testEscN2()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.escn2")));
		LogString expected(1, 0x0A);
		expected.append(LOG4CXX_STR(" in value"));
		LOGUNIT_ASSERT_EQUAL(expected, actual);
	}

	/**
	 *  Test \r within key, see LOGCXX-293.
	*/
	void testEscR1()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString key(LOG4CXX_STR("propertiestestcase.escr1"));
		key.append(1, 0x0D);
		LogString actual(properties.getProperty(key));
		LOGUNIT_ASSERT_EQUAL(LogString(LOG4CXX_STR("key contains cr")), actual);
	}



	/**
	 *  Test \r in value, see LOGCXX-293.
	*/
	void testEscR2()
	{
		FileInputStreamPtr propFile(
			new FileInputStream(LOG4CXX_STR("input/propertiestestcase.properties")));
		Properties properties;
		properties.load(propFile);
		LogString actual(properties.getProperty(LOG4CXX_STR("propertiestestcase.escr2")));
		LogString expected(1, 0x0D);
		expected.append(LOG4CXX_STR(" in value"));
		LOGUNIT_ASSERT_EQUAL(expected, actual);
	}


};


LOGUNIT_TEST_SUITE_REGISTRATION(PropertiesTestCase);
