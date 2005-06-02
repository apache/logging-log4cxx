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

#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>
#include <iostream>
#include <log4cxx/private/log4cxx_private.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

bool LogLog::debugEnabled = false;
bool LogLog::quietMode = false;

void LogLog::setInternalDebugging(bool debugEnabled)
{
        LogLog::debugEnabled = debugEnabled;
}

void LogLog::debug(const LogString& msg)
{
        if(debugEnabled && !quietMode)
        {
                emit(msg);
        }
}

void LogLog::debug(const LogString& msg, const std::exception& e)
{
        debug(msg);
        emit(e.what());
}


void LogLog::error(const LogString& msg)
{
        if(quietMode)
                return;
        emit(msg);
}

void LogLog::error(const LogString& msg, const std::exception& e)
{
        error(msg);
        emit(e.what());
}

void LogLog::setQuietMode(bool quietMode)
{
        LogLog::quietMode = quietMode;
}

void LogLog::warn(const LogString& msg)
{
        if(quietMode)
                return;

        emit(msg);
}

void LogLog::warn(const LogString& msg, const std::exception& e)
{
        warn(msg);
        emit(e.what());
}


void LogLog::emit(const std::string& msg) {
    std::cerr << "log4cxx: " << msg << std::endl;
}

#if LOG4CXX_HAS_WCHAR_T
void LogLog::emit(const std::wstring& msg) {
#if LOG4CXX_HAS_STD_WCOUT
    std::wcerr << L"log4cxx: " << msg << std::endl;
#else
    LOG4CXX_ENCODE_CHAR(encoded, msg);
    std::cerr << "log4cxx: " << encoded << std::endl;
#endif
}
#endif
