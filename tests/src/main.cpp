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

#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <stdexcept>
#include <iostream>

#include <log4cxx/logger.h>
#include <apr_general.h>
#include "insertwide.h"
#include <log4cxx/helpers/transcoder.h>

//
//  initializing a logger will cause the APR used by log4cxx library to be initialized
//
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("log4cxx_unittest"));

int main( int argc, const char * const argv[])
{
        apr_app_initialize(&argc, &argv, NULL);
        CppUnit::TextUi::TestRunner runner;

        CppUnit::TestFactoryRegistry &registry =
                CppUnit::TestFactoryRegistry::getRegistry();

        runner.addTest(registry.makeTest());

        bool wasSuccessful = true;
        if (argc > 1)
        {
                for (int n = 1; n < argc; n++)
                {
                        try
                        {
                                wasSuccessful = runner.run(argv[n], false) && wasSuccessful;
                        }
                        catch(std::exception& e)
                        {
                                std::cout << e.what() << std::endl;
                        }
                        catch (...) {
                                std::cout << "Unexpected exception";
                        }
                }
        }
        else
        {
                bool wasSuccessful = runner.run("", false);
        }

        apr_terminate();
        return wasSuccessful ? EXIT_SUCCESS : EXIT_FAILURE;
}

std::ostream& operator<<(std::ostream& os,
                               const std::wstring& str) {
    std::string encoded;
    log4cxx::helpers::Transcoder::encode(str, encoded);
    os << encoded;
    return os;
}

