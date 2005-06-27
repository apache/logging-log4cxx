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

#include <stdlib.h>
#include <log4cxx/stream.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/ndc.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

int main()
{
    int result = EXIT_SUCCESS;
    try
    {
                BasicConfigurator::configure();
                LoggerPtr rootLogger = Logger::getRootLogger();

                NDC::push("trivial context");

                log4cxx::logstream logstream(rootLogger, Level::DEBUG);
                logstream << "debug message " << 1 << LOG4CXX_ENDMSG;
                logstream.setLevel(Level::INFO);
#if LOG4CXX_HAS_WCHAR_T
                logstream << L"info message" << LOG4CXX_ENDMSG;
#else
                logstream << "info message" << LOG4CXX_ENDMSG;
#endif
                logstream << Level::WARN << "warn message" << LOG4CXX_ENDMSG;
#if LOG4CXX_HAS_WCHAR_T
                logstream << Level::ERROR << L"error message" << LOG4CXX_ENDMSG;
#else
                logstream << Level::ERROR << "error message" << LOG4CXX_ENDMSG;
#endif
                logstream << Level::FATAL << "fatal message" << LOG4CXX_ENDMSG;


                NDC::pop();
        }
        catch(std::exception&)
        {
                result = EXIT_FAILURE;
        }

    return result;
}
