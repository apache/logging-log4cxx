/***************************************************************************
                          optionconvertertestcase.cpp
                             -------------------
    begin                : 2004/01/20
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
* Copyright (C) The Apache Software Foundation. All rights reserved.      *
*                                                                         *
* This software is published under the terms of the Apache Software       *
* License version 1.1, a copy of which has been included with this        *
* distribution in the license.apl file.                                   *
***************************************************************************/
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/system.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;

#define MAX 1000

class OptionConverterTestCase : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(OptionConverterTestCase);
		CPPUNIT_TEST(varSubstTest1);
		CPPUNIT_TEST(varSubstTest2);
		CPPUNIT_TEST(varSubstTest3);
		CPPUNIT_TEST(varSubstTest4);
		CPPUNIT_TEST(varSubstTest5);
	CPPUNIT_TEST_SUITE_END();
	
	Properties props;
	Properties nullProperties;
	
public:
	void setUp()
	{
		props.setProperty(_T("TOTO"), _T("wonderful"));
		props.setProperty(_T("key1"), _T("value1"));
		props.setProperty(_T("key2"), _T("value2"));
		System::setProperties(props);
	}

	void tearDown()
	{
	}
  
	void varSubstTest1()
	{
		String r;
		
		r = OptionConverter::substVars(_T("hello world."), nullProperties);
		//CPPUNIT_ASSERT_EQUAL(String(_T("hello world.")), r);

		r = OptionConverter::substVars(_T("hello ${TOTO} world."), nullProperties);

		//CPPUNIT_ASSERT_EQUAL(String(_T("hello wonderful world.")), r);
	}

  
	void varSubstTest2()
	{
		String r;
		
		r = OptionConverter::substVars(_T("Test2 ${key1} mid ${key2} end."),
			nullProperties);
		CPPUNIT_ASSERT(r == _T("Test2 value1 mid value2 end."));
	}
	
	
	void varSubstTest3() 
	{
		String r;
		
		r = OptionConverter::substVars(
			_T("Test3 ${unset} mid ${key1} end."), nullProperties);
		CPPUNIT_ASSERT(r == _T("Test3  mid value1 end."));
	}
	
	
	void varSubstTest4()
	{
		String res;
		String val = _T("Test4 ${incomplete ");
		try 
		{
			res = OptionConverter::substVars(val, nullProperties);
		}
		catch(IllegalArgumentException& e)
		{
			String errorMsg = e.getMessage();
			CPPUNIT_ASSERT(errorMsg == String(_T("\""))+val
				+ _T("\" has no closing brace. Opening brace at position 6."));
		}
	}
	
	
	void varSubstTest5()
	{
		Properties props;
		props.setProperty(_T("p1"), _T("x1"));
		props.setProperty(_T("p2"), _T("${p1}"));
		String res = OptionConverter::substVars(_T("${p2}"), props);
		CPPUNIT_ASSERT(res == _T("x1"));
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION(OptionConverterTestCase);
