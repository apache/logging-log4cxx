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

#include <log4cxx/mdc.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/threadspecificdata.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

MDC::MDC(const LogString& key1, const LogString& value) : key(key1)
{
        put(key1, value);
}

MDC::~MDC()
{
        remove(key);
}

void MDC::putLogString(const LogString& key, const LogString& value)
{
        Map& map = ThreadSpecificData::getCurrentThreadMap();
        map[key] = value;
}

#if LOG4CXX_HAS_WCHAR_T
void MDC::put(const std::wstring& key, const std::wstring& value)
{
        LOG4CXX_DECODE_WCHAR(lkey, key);
        LOG4CXX_DECODE_WCHAR(lvalue, value);
        putLogString(lkey, lvalue);
}
#endif

void MDC::put(const std::string& key, const std::string& value)
{
        LOG4CXX_DECODE_CHAR(lkey, key);
        LOG4CXX_DECODE_CHAR(lvalue, value);
        putLogString(lkey, lvalue);
}

bool MDC::get(const LogString& key, LogString& value)
{
        Map& map = ThreadSpecificData::getCurrentThreadMap();

        Map::iterator it = map.find(key);
        if (it != map.end()) {
                value.append(it->second);
                return true;
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

#if LOG4CXX_HAS_WCHAR_T
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
#endif

bool MDC::remove(const LogString& key, LogString& value)
{
        Map::iterator it;
        Map& map = ThreadSpecificData::getCurrentThreadMap();
        if ((it = map.find(key)) != map.end())
        {
                value = it->second;
                map.erase(it);
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

#if LOG4CXX_HAS_WCHAR_T
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
#endif

void MDC::clear()
{
        Map& map = ThreadSpecificData::getCurrentThreadMap();
        map.erase(map.begin(), map.end());
}

