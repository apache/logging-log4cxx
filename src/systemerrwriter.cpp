/*
 * Copyright 2003,2005 The Apache Software Foundation.
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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/systemerrwriter.h>
#include <log4cxx/helpers/transcoder.h>
#include <stdio.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

IMPLEMENT_LOG4CXX_OBJECT(SystemErrWriter)

SystemErrWriter::SystemErrWriter() {
}

SystemErrWriter::~SystemErrWriter() {
}

void SystemErrWriter::close(Pool& p) {
}

void SystemErrWriter::flush(Pool& p) {
}

void SystemErrWriter::write(const LogString& str, Pool& p) {
#if LOG4CXX_HAS_WCHAR_T
#if LOG4CXX_FORCE_WIDE_CONSOLE
    if (true) {
#else
    if (fwide(stderr, 0) > 0) {
#endif
    	LOG4CXX_ENCODE_WCHAR(msg, str);
        fputws(msg.c_str(), stderr);
    } else {
#else
    {
#endif
    	LOG4CXX_ENCODE_CHAR(msg, str);
        fputs(msg.c_str(), stderr);
    }
}
