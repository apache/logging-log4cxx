/***************************************************************************
                          optionconverter.cpp  -  class OptionConverter
                             -------------------
    begin                : mer avr 30 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/helpers/optionconverter.h>
#include <algorithm>
#include <ctype.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/helpers/exception.h>
#include <stdlib.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/level.h>
#include <log4cxx/helpers/object.h>
#include <log4cxx/helpers/class.h>
#include <log4cxx/helpers/loader.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

tstring OptionConverter::DELIM_START = _T("${");
TCHAR OptionConverter::DELIM_STOP  = _T('}');
int OptionConverter::DELIM_START_LEN = 2;
int OptionConverter::DELIM_STOP_LEN  = 1;

namespace {
    // Function object to turn a lower case character into an upper case one
    class ToUpper {
    public:
        void operator()(TCHAR& c){c = toupper(c);}
    };
}

bool OptionConverter::toBoolean(const tstring& value, bool dEfault)
{
	if (value.empty())
	{
		return dEfault;
	}

	tstring trimmedVal = StringHelper::toLowerCase(StringHelper::trim(value));

	if (trimmedVal == _T("true"))
	{
		return true;
	}
	if (trimmedVal == _T("false"))
	{
		return false;
	}

	return dEfault;
}

int OptionConverter::toInt(const tstring& value, int dEfault)
{
	if (value.empty())
	{
		return dEfault;
	}

	return (int)ttol(StringHelper::trim(value).c_str());
}

long OptionConverter::toFileSize(const tstring& value, long dEfault)
{
	if(value.empty())
	{
		return dEfault;
	}

	tstring s = StringHelper::toLowerCase(StringHelper::trim(value));

	long multiplier = 1;
	int index;
	
	if((index = s.find(_T("kb"))) != -1)
	{
		multiplier = 1024;
		s = s.substr(0, index);
	}
	else if((index = s.find(_T("mb"))) != -1) 
	{
		multiplier = 1024*1024;
		s = s.substr(0, index);
	}
	else if((index = s.find(_T("gb"))) != -1)
	{
		multiplier = 1024*1024*1024;
		s = s.substr(0, index);
	}
	if(!s.empty())
	{
		return ttol(s.c_str()) * multiplier;
	}

	return dEfault;
}

tstring OptionConverter::findAndSubst(const tstring& key, Properties& props)
{
	tstring value = props.getProperty(key);

	if(value.empty())
		return value;

	try
	{
		return substVars(value, props);
	}
	catch(IllegalArgumentException& e)
	{
		LogLog::error(_T("Bad option value [")+value+_T("]."), e);
		return value;
	}
}

tstring OptionConverter::substVars(const tstring& val, Properties& props)
{
	tostringstream sbuf;

	int i = 0;
	int j, k;

	while(true)
	{
		j = val.find(DELIM_START, i);
		if(j == -1)
		{
			// no more variables
			if(i==0)
			{ // this is a simple string
				return val;
			}
			else
			{ // add the tail string which contails no variables and return the result.
				sbuf << val.substr(i, val.length() - i);
				return sbuf.str();
			}
		}
		else
		{
			sbuf << val.substr(i, j - i);
			k = val.find(DELIM_STOP, j);
			if(k == -1)
			{
				tostringstream oss;
				oss << _T("\"") << val
					<< _T("\" has no closing brace. Opening brace at position ")
					<< j << _T(".");
				throw new IllegalArgumentException(oss.str());
			}
			else
			{
				j += DELIM_START_LEN;
				tstring key = val.substr(j, k - j);
				// first try in System properties
				tstring replacement = getSystemProperty(key, _T(""));
				// then try props parameter
				if(replacement.empty())
				{
					replacement = props.getProperty(key);
				}

				if(!replacement.empty())
				{
					// Do variable substitution on the replacement string
					// such that we can solve "Hello ${x2}" as "Hello p1"
					// the where the properties are
					// x1=p1
					// x2=${x1}
					tstring recursiveReplacement = substVars(replacement, props);
					sbuf << (recursiveReplacement);
				}
				i = k + DELIM_STOP_LEN;
			}
		}
	}
}

tstring OptionConverter::getSystemProperty(const tstring& key, const tstring& def)
{
	if (!key.empty())
	{
		USES_CONVERSION;
		tstring value = A2T(::getenv(T2A(def.c_str())));

		if (!value.empty())
		{
			return value;
		}
		else
		{
			return def;
		}
	}
	else
	{
		return def;
	}
}

const Level& OptionConverter::toLevel(const tstring& value, const Level& defaultValue)
{
	return Level::toLevel(value, defaultValue);
}


ObjectPtr OptionConverter::instantiateByKey(Properties& props, const tstring& key,
	const Class& superClass, ObjectPtr defaultValue)
{
	// Get the value of the property in string form
	tstring className = findAndSubst(key, props);
	if(className.empty())
	{
		LogLog::error(_T("Could not find value for key ") + key);
		return defaultValue;
	}

	tstring::size_type pos = className.find_last_of(_T('.'));
	if (pos != tstring::npos)
	{
		className = className.substr(pos + 1);
	}

	// Trim className to avoid trailing spaces that cause problems.
	return OptionConverter::instantiateByClassName(
		StringHelper::trim(className), superClass, defaultValue);
}

ObjectPtr OptionConverter::instantiateByClassName(const tstring& className,
	const Class& superClass, ObjectPtr defaultValue)
{
	if(!className.empty())
	{
		try
		{
			const Class& classObj = Loader::loadClass(className);
			ObjectPtr newObject =  classObj.newInstance();
			if (!newObject->instanceof(superClass))
			{
				return defaultValue;
			}

			return newObject;
		}
		catch (Exception& e)
		{
			LogLog::error(_T("Could not instantiate class [") + className
				+ _T("]."), e);
		}
	}
	return defaultValue;
}
