/*
 * Copyright 2003,2004 The Apache Software Foundation.
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

#include <log4cxx/mdc.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

helpers::ThreadSpecificData MDC::threadSpecificData;

MDC::MDC(const LogString& key, const LogString& value) : key(key)
{
	put(key, value);
}

MDC::~MDC()
{
	remove(key);
}

MDC::Map * MDC::getCurrentThreadMap()
{
	return (MDC::Map *)threadSpecificData.GetData();
}

void MDC::setCurrentThreadMap(MDC::Map * map)
{
	threadSpecificData.SetData((void *)map);
}

void MDC::putLogString(const LogString& key, const LogString& value)
{
	Map * map = getCurrentThreadMap();

	if (map == 0)
	{
		map = new Map;
		setCurrentThreadMap(map);
	}

	(*map)[key] = value;
}


void MDC::put(const std::wstring& key, const std::wstring& value)
{
        LOG4CXX_DECODE_WCHAR(lkey, key);
        LOG4CXX_DECODE_WCHAR(lvalue, value);
        putLogString(lkey, lvalue);
}

void MDC::put(const std::string& key, const std::string& value)
{
        LOG4CXX_DECODE_CHAR(lkey, key);
        LOG4CXX_DECODE_CHAR(lvalue, value);
        putLogString(lkey, lvalue);
}

bool MDC::get(const LogString& key, LogString& value)
{
	Map::iterator it;
	Map * map = getCurrentThreadMap();

	if (map != 0)
	{
		Map::iterator it = map->find(key);
		if (it != map->end()) {
                        value = it->second;
			return true;
		}
	}
        return false;
}

std::string MDC::get(const std::string& key)
{
        LOG4CXX_DECODE_CHAR(lkey, key);
        LogString lvalue;
        if (get(lkey, lvalue)) {
          LOG4CXX_ENCODE_CHAR(value, lvalue);
          return value;
        }
        return std::string();
}

std::wstring MDC::get(const std::wstring& key)
{
        LOG4CXX_DECODE_WCHAR(lkey, key);
        LogString lvalue;
        if (get(lkey, lvalue)) {
          LOG4CXX_ENCODE_WCHAR(value, lvalue);
          return value;
        }
        return std::wstring();
}


bool MDC::remove(const LogString& key, LogString& value)
{
	Map::iterator it;
	Map * map = getCurrentThreadMap();
	if (map != 0 && (it = map->find(key)) != map->end())
	{
		value = it->second;
		map->erase(it);
                return true;
	}
        return false;
}

std::string MDC::remove(const std::string& key)
{
        LOG4CXX_DECODE_CHAR(lkey, key);
        LogString lvalue;
        if (remove(lkey, lvalue)) {
          LOG4CXX_ENCODE_CHAR(value, lvalue);
          return value;
        }
        return std::string();
}

std::wstring MDC::remove(const std::wstring& key)
{
        LOG4CXX_DECODE_WCHAR(lkey, key);
        LogString lvalue;
        if (remove(lkey, lvalue)) {
          LOG4CXX_ENCODE_WCHAR(value, lvalue);
          return value;
        }
        return std::wstring();
}


void MDC::clear()
{
	Map * map = getCurrentThreadMap();
	if(map != 0)
	{
		delete map;
		setCurrentThreadMap(0);
	}
}

const MDC::Map MDC::getContext()
{
	Map * map = getCurrentThreadMap();
	if(map != 0)
	{
		return *map;
	}
	else
	{
		return Map();
	}
}

void MDC::setContext(Map& map)
{
	Map * currentMap = getCurrentThreadMap();

	if (currentMap == 0)
	{
		currentMap = new Map;
		setCurrentThreadMap(currentMap);
	}

	*currentMap = map;
}
