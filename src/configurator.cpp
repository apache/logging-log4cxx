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

#include <log4cxx/spi/configurator.h>
#include <assert.h>

using namespace log4cxx;
using namespace log4cxx::spi;

IMPLEMENT_LOG4CXX_OBJECT(Configurator);




#define REFERENCE_LOG4CXX_OBJECT(object) \
namespace log4cxx { namespace classes { extern bool object##IsRegistered; } }

#define STATUS_LOG4CXX_OBJECT(object) \
log4cxx::classes::object##IsRegistered


//
//   force all common Appenders and Layouts to be referenced here
//     so that a static link including a configurator is
//     required to pull them in
//
REFERENCE_LOG4CXX_OBJECT(AsyncAppender)
REFERENCE_LOG4CXX_OBJECT(ConsoleAppender)
REFERENCE_LOG4CXX_OBJECT(FileAppender)
#ifdef LOG4CXX_HAVE_ODBC
REFERENCE_LOG4CXX_OBJECT(ODBCAppender)
#endif
#if defined(WIN32) || defined(_WIN32)
REFERENCE_LOG4CXX_OBJECT(NTEventLogAppender)
REFERENCE_LOG4CXX_OBJECT(OutputDebugStringAppender)
#endif
REFERENCE_LOG4CXX_OBJECT(RollingFileAppender)
#ifdef LOG4CXX_HAVE_SMTP
REFERENCE_LOG4CXX_OBJECT(SMTPAppender)
#endif
REFERENCE_LOG4CXX_OBJECT(SocketAppender)
REFERENCE_LOG4CXX_OBJECT(SocketHubAppender)
REFERENCE_LOG4CXX_OBJECT(SyslogAppender)
REFERENCE_LOG4CXX_OBJECT(TelnetAppender)
REFERENCE_LOG4CXX_OBJECT(WriterAppender)
REFERENCE_LOG4CXX_OBJECT(XMLSocketAppender)
//REFERENCE_LOG4CXX_OBJECT(DateLayout)
REFERENCE_LOG4CXX_OBJECT(HTMLLayout)
REFERENCE_LOG4CXX_OBJECT(Layout)
REFERENCE_LOG4CXX_OBJECT(PatternLayout)
REFERENCE_LOG4CXX_OBJECT(SimpleLayout)
REFERENCE_LOG4CXX_OBJECT(TTCCLayout)
REFERENCE_LOG4CXX_OBJECT(XMLLayout)
REFERENCE_LOG4CXX_OBJECT(LevelMatchFilter)
REFERENCE_LOG4CXX_OBJECT(LevelRangeFilter)
REFERENCE_LOG4CXX_OBJECT(StringMatchFilter)



Configurator::Configurator() {
    initialized =
        STATUS_LOG4CXX_OBJECT(AsyncAppender) &&
        STATUS_LOG4CXX_OBJECT(ConsoleAppender) &&
        STATUS_LOG4CXX_OBJECT(FileAppender) &&
#ifdef LOG4CXX_HAVE_ODBC
        STATUS_LOG4CXX_OBJECT(ODBCAppender) &&
#endif
#if defined(WIN32) || defined(_WIN32)
        STATUS_LOG4CXX_OBJECT(NTEventLogAppender) &&
        STATUS_LOG4CXX_OBJECT(OutputDebugStringAppender) &&
#endif
        STATUS_LOG4CXX_OBJECT(RollingFileAppender) &&
#ifdef LOG4CXX_HAVE_SMTP
        STATUS_LOG4CXX_OBJECT(SMTPAppender) &&
#endif
        STATUS_LOG4CXX_OBJECT(SocketAppender) &&
        STATUS_LOG4CXX_OBJECT(SocketHubAppender) &&
        STATUS_LOG4CXX_OBJECT(SyslogAppender) &&
        STATUS_LOG4CXX_OBJECT(TelnetAppender) &&
        STATUS_LOG4CXX_OBJECT(WriterAppender) &&
        STATUS_LOG4CXX_OBJECT(XMLSocketAppender) &&
 //       STATUS_LOG4CXX_OBJECT(DateLayout) &&
        STATUS_LOG4CXX_OBJECT(HTMLLayout) &&
        STATUS_LOG4CXX_OBJECT(Layout) &&
        STATUS_LOG4CXX_OBJECT(PatternLayout) &&
        STATUS_LOG4CXX_OBJECT(SimpleLayout) &&
        STATUS_LOG4CXX_OBJECT(TTCCLayout) &&
        STATUS_LOG4CXX_OBJECT(XMLLayout) &&
        STATUS_LOG4CXX_OBJECT(LevelMatchFilter) &&
        STATUS_LOG4CXX_OBJECT(LevelRangeFilter) &&
        STATUS_LOG4CXX_OBJECT(StringMatchFilter);
}
