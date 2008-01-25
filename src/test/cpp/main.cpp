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

#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <stdexcept>
#include <iostream>

#include <log4cxx/logger.h>
#include <apr_general.h>
#include "insertwide.h"
#include <log4cxx/helpers/transcoder.h>
#include <cppunit/Outputter.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TextTestResult.h>
#include <cppunit/TextOutputter.h>
#include <cppunit/TextTestProgressListener.h>
#include <cppunit/TestResult.h>
#include <iostream>
#include <stdexcept>
#include <log4cxx/basicconfigurator.h>
#include <locale.h>

#include <log4cxx/log4cxx.h>
#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>

extern CPPUNIT_NS::Test* createTestCase1();
extern CPPUNIT_NS::Test* createTestCase3();

extern CPPUNIT_NS::Test* createTestCase2();
extern CPPUNIT_NS::Test* createTestCase4();
extern CPPUNIT_NS::Test* createSocketServerTestCase();

//
//  initializing a logger will cause the APR used by log4cxx library to be initialized
//
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("log4cxx_unittest"));

#if defined(_WIN32_WCE)
#define LOG4CXX_USE_WMAIN 1
#endif

#if defined(LOG4CXX_USE_WMAIN)
int wmain(int argc, const wchar_t* const * wargv) {
    char** argv = new char*[argc];
    {
        setlocale(LC_ALL, "");
        for(int i = 0; i < argc; i++) {
            size_t len = wcslen(wargv[i]) + 1;
            argv[i] = new char[len];
            //
            //   truncate characters since argument names should 
            //      only be ASCII
            for(size_t j = 0; j < len; j++) {
                argv[i][j] = (char) wargv[i][j];
            }
        }
    }
    apr_app_initialize(&argc, (const char* const **) &argv, NULL);
#else
int main(int argc, const char* const * argv) {
        setlocale(LC_ALL, "");
        apr_app_initialize(&argc, &argv, NULL);
#endif
        CppUnit::TextUi::TestRunner runner;

        CppUnit::TestFactoryRegistry &registry =
                CppUnit::TestFactoryRegistry::getRegistry();

        runner.addTest(registry.makeTest());

        bool wasSuccessful = true;
        if (argc > 1)
        {
             bool runAll = false;
                for (int n = 1; n < argc; n++)
                {
               std::string testName(argv[n]);
               //
               //  if any name starts with a +
               //     run it in addition to all tests
               if (argv[n][0] == '+') {
                  runAll = true;
                  testName.erase(0, 1);
               }

               //
               //   if the test case starts with TestCase
               //
               if (testName.length() >= 9 && testName.compare(0, 8, "TestCase") == 0) {
                  char testN = testName[8];
                  switch(testN) {
                     case '1':
                        runner.addTest(createTestCase1());
                        break;
                     case '3':
                        runner.addTest(createTestCase3());
                        break;
                     case '2':
                        runner.addTest(createTestCase2());
                        break;
                     case '4':
                        runner.addTest(createTestCase4());
                        break;
                     default:
                        break;
                  }
               }
               
               if (testName == "SocketServerTestCase") {
                    runner.addTest(createSocketServerTestCase());
               }

               if (runAll) {
                  wasSuccessful = runner.run("", false);
               } else {
                  try
                  {
                     wasSuccessful = runner.run(testName, false) && wasSuccessful;
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
        }
        else
        {
                wasSuccessful = runner.run("", false);
        }

        apr_terminate();
#if defined(LOG4CXX_USE_WMAIN)
    for(int i = 0; i < argc; i++) {
        delete [] (argv[i]);
    }
    delete [] argv;
#endif
        return wasSuccessful ? EXIT_SUCCESS : EXIT_FAILURE;
}
#if LOG4CXX_WCHAR_T_API
std::ostream& operator<<(std::ostream& os,
                               const std::wstring& str) {
    LOG4CXX_DECODE_WCHAR(tmp, str);
    LOG4CXX_ENCODE_CHAR(encoded, tmp);
    os << encoded;
    return os;
}
#endif

#if LOG4CXX_LOGCHAR_IS_UNICHAR || LOG4CXX_UNICHAR_API || LOG4CXX_CFSTRING_API
std::ostream& operator<<(std::ostream& os,
                               const std::basic_string<log4cxx::UniChar>& str) {
    LOG4CXX_DECODE_UNICHAR(tmp, str);
    LOG4CXX_ENCODE_CHAR(encoded, tmp);
    os << encoded;
    return os;
}
#endif

