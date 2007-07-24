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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>
#include <iostream>
#include <log4cxx/private/log4cxx_private.h>
#include <log4cxx/helpers/synchronized.h>
#include <log4cxx/helpers/aprinitializer.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

LogLog::LogLog() : mutex((log4cxx_pool_t*) APRInitializer::getRootPool()) {
    synchronized sync(mutex);
    debugEnabled = false;
    quietMode = false;
}

LogLog& LogLog::getInstance() {
    static LogLog internalLogger;
    return internalLogger;
}


void LogLog::setInternalDebugging(bool debugEnabled1)
{
        synchronized sync(getInstance().mutex);
        getInstance().debugEnabled = debugEnabled1;
}

void LogLog::debug(const LogString& msg)
{
        synchronized sync(getInstance().mutex);
        if(getInstance().debugEnabled && !getInstance().quietMode)
        {
                emit(msg);
        }
}

void LogLog::debug(const LogString& msg, const std::exception& e)
{
        synchronized sync(getInstance().mutex);
        debug(msg);
        emit(e.what());
}


void LogLog::error(const LogString& msg)
{
        synchronized sync(getInstance().mutex);
        if(!getInstance().quietMode) {
            emit(msg);
        }
}

void LogLog::error(const LogString& msg, const std::exception& e)
{
        synchronized sync(getInstance().mutex);
        error(msg);
        emit(e.what());
}

void LogLog::setQuietMode(bool quietMode1)
{
        synchronized sync(getInstance().mutex);
        getInstance().quietMode = quietMode1;
}

void LogLog::warn(const LogString& msg)
{
        synchronized sync(getInstance().mutex);
        if(!getInstance().quietMode) {
           emit(msg);
        }
}

void LogLog::warn(const LogString& msg, const std::exception& e)
{
        synchronized sync(getInstance().mutex);
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
