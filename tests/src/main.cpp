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
#include <cppunit/Outputter.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TextTestResult.h>
#include <cppunit/TextOutputter.h>
#include <cppunit/TextTestProgressListener.h>
#include <cppunit/TestResult.h>
#include <cppunit/ui/text/TextTestRunner.h>
#include <iostream>
#include <stdexcept>
#include <log4cxx/basicconfigurator.h>





class ModTextTestRunner : public CPPUNIT_NS::TestRunner
{
public:
ModTextTestRunner( CPPUNIT_NS::Outputter *outputter = NULL )
    : m_outputter( outputter )
    , m_result( new CPPUNIT_NS::TestResultCollector() )
    , m_eventManager( new CPPUNIT_NS::TestResult() )
{
  if ( !m_outputter )
    m_outputter = new CPPUNIT_NS::TextOutputter( m_result, std::cout );
  m_eventManager->addListener( m_result );
}


~ModTextTestRunner()
{
  delete m_eventManager;
  delete m_outputter;
  delete m_result;
}


/*! Runs the named test case.
 *
 * \param testName Name of the test case to run. If an empty is given, then
 *                 all added tests are run. The name can be the name of any
 *                 test in the hierarchy.
 * \param doWait if \c true then the user must press the RETURN key
 *               before the run() method exit.
 * \param doPrintResult if \c true (default) then the test result are printed
 *                      on the standard output.
 * \param doPrintProgress if \c true (default) then TextTestProgressListener is
 *                        used to show the progress.
 * \return \c true is the test was successful, \c false if the test
 *         failed or was not found.
 */
bool
run( std::string testName = "",
                       bool doWait = false,
                       bool doPrintResult = true,
                       bool doPrintProgress = true )
{
  CPPUNIT_NS::BriefTestProgressListener progress;
  if ( doPrintProgress )
    m_eventManager->addListener( &progress );

  CPPUNIT_NS::TestRunner *pThis = this;
  pThis->run( *m_eventManager, testName );

  if ( doPrintProgress )
    m_eventManager->removeListener( &progress );

  printResult( doPrintResult );
  wait( doWait );

  return m_result->wasSuccessful();
}


void
wait( bool doWait )
{
  if ( doWait )
  {
    std::cout << "<RETURN> to continue" << std::endl;
    std::cin.get ();
  }
}


void
printResult( bool doPrintResult )
{
  std::cout << std::endl;
  if ( doPrintResult )
    m_outputter->write();
}


/*! Returns the result of the test run.
 * Use this after calling run() to access the result of the test run.
 */
CPPUNIT_NS::TestResultCollector &
result() const
{
  return *m_result;
}


/*! Returns the event manager.
 * The instance of TestResult results returned is the one that is used to run the
 * test. Use this to register additional TestListener before running the tests.
 */
CPPUNIT_NS::TestResult &
eventManager() const
{
  return *m_eventManager;
}


/*! Specifies an alternate outputter.
 *
 * Notes that the outputter will be use after the test run only if \a printResult was
 * \c true.
 * \param outputter New outputter to use. The previous outputter is destroyed.
 *                  The TextTestRunner assumes ownership of the outputter.
 * \see CompilerOutputter, XmlOutputter, TextOutputter.
 */
void
setOutputter( CPPUNIT_NS::Outputter *outputter )
{
  delete m_outputter;
  m_outputter = outputter;
}


  CPPUNIT_NS::TestResultCollector *m_result;
  CPPUNIT_NS::TestResult *m_eventManager;
  CPPUNIT_NS::Outputter *m_outputter;
};

//
//  initializing a logger will cause the APR used by log4cxx library to be initialized
//
log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("log4cxx_unittest"));

int main( int argc, const char * const argv[])
{
        apr_app_initialize(&argc, &argv, NULL);
        ModTextTestRunner runner;

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
                wasSuccessful = runner.run("", false);
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

