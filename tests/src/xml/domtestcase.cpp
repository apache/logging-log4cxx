/*
 * Copyright 2003-2005 The Apache Software Foundation.
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

#include <log4cxx/portability.h>

#ifdef HAVE_XML

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>

#include "../util/compare.h"
#include "xlevel.h"
#include "../util/controlfilter.h"
#include "../util/iso8601filter.h"
#include "../util/threadfilter.h"
#include "../util/transformer.h"
#include <iostream>
#include <log4cxx/file.h>
#include <log4cxx/fileappender.h>
#include <apr_pools.h>
#include <apr_file_io.h>

#define LOG4CXX_TEST_STR(x) L##x

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;


#define TEST1_1A_PAT \
        "(DEBUG|INFO |WARN |ERROR|FATAL) \\w*\\.\\w* - Message [0-9]"

#define TEST1_1B_PAT "(DEBUG|INFO |WARN |ERROR|FATAL) root - Message [0-9]"

#define TEST1_2_PAT "^[0-9]\\{4\\}-[0-9]\\{2\\}-[0-9]\\{2\\} [0-9]\\{2\\}:[0-9]\\{2\\}:[0-9]\\{2\\},[0-9]\\{3\\} " \
        "\\[0x[0-9A-F]*]\\ (DEBUG|INFO|WARN|ERROR|FATAL) .* - Message [0-9]"

class DOMTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(DOMTestCase);
                CPPUNIT_TEST(test1);
                CPPUNIT_TEST(test2);
                CPPUNIT_TEST(test3);
        CPPUNIT_TEST_SUITE_END();

        LoggerPtr root;
        LoggerPtr logger;

        static const File TEMP_A1;
        static const File TEMP_A2;
        static const File FILTERED_A1;
        static const File FILTERED_A2;
        static const File TEMP_A1_2;
        static const File TEMP_A2_2;
        static const File FILTERED_A1_2;
        static const File FILTERED_A2_2;

public:
        void setUp()
        {
                root = Logger::getRootLogger();
                logger = Logger::getLogger(LOG4CXX_TEST_STR("org.apache.log4j.xml.DOMTestCase"));
        }

        void tearDown()
        {
                root->getLoggerRepository()->resetConfiguration();
        }


        void test1() {
                DOMConfigurator::configure(LOG4CXX_TEST_STR("input/xml/DOMTestCase1.xml"));
                common();

                ControlFilter cf1;
                cf1 << TEST1_1A_PAT << TEST1_1B_PAT;

                ControlFilter cf2;
                cf2 << TEST1_2_PAT;

                ThreadFilter threadFilter;
                ISO8601Filter iso8601Filter;

                std::vector<Filter *> filters1;
                filters1.push_back(&cf1);

                std::vector<Filter *> filters2;
                filters2.push_back(&cf2);
                filters2.push_back(&threadFilter);
                filters2.push_back(&iso8601Filter);

                try
                {
                        Transformer::transform(TEMP_A1, FILTERED_A1, filters1);
                        Transformer::transform(TEMP_A2, FILTERED_A2, filters2);
                }
                catch(UnexpectedFormatException& e)
                {
                    std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                const File witness1(L"witness/dom.A1.1");
                const File witness2(L"witness/dom.A2.1");
                //   TODO: A1 doesn't contain duplicate entries
                //
                //                CPPUNIT_ASSERT(Compare::compare(FILTERED_A1, witness1));
                CPPUNIT_ASSERT(Compare::compare(FILTERED_A2, witness2));
        }

        //
        //   Same test but backslashes instead of forward
        //
        void test2() {
                DOMConfigurator::configure(LOG4CXX_TEST_STR("input\\xml\\DOMTestCase2.xml"));
                common();

                ThreadFilter threadFilter;
                ISO8601Filter iso8601Filter;

                std::vector<Filter *> filters1;

                std::vector<Filter *> filters2;
                filters2.push_back(&threadFilter);
                filters2.push_back(&iso8601Filter);

                try
                {
                        Transformer::transform(TEMP_A1_2, FILTERED_A1_2, filters1);
                        Transformer::transform(TEMP_A2_2, FILTERED_A2_2, filters2);
                }
                catch(UnexpectedFormatException& e)
                {
                    std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                const File witness1(L"witness/dom.A1.2");
                const File witness2(L"witness/dom.A2.2");
                //   TODO: A1 doesn't contain duplicate entries
                //
                //                CPPUNIT_ASSERT(Compare::compare(FILTERED_A1, witness1));
                CPPUNIT_ASSERT(Compare::compare(FILTERED_A2, witness2));
        }

        void test3() {
                DOMConfigurator::configure(LOG4CXX_STR("input/xml/DOMTestCase3.xml"));
                LoggerPtr root(Logger::getRootLogger());
                FileAppenderPtr appender(root->getAppender(LOG4CXX_STR("A1")));
                File file(appender->getFile());
                std::string osname(file.getOSName());
                CPPUNIT_ASSERT_EQUAL((std::string) "e:\\tmp\\temp.A1", osname);
        }


        void common()
        {
                int i = -1;
                std::ostringstream os;
                os << "Message " << ++i;

                LOG4CXX_DEBUG(logger, os.str());
                LOG4CXX_DEBUG(root, os.str());

                os.str("");
                os << "Message " << ++i;
                LOG4CXX_INFO(logger,os.str());
                LOG4CXX_INFO(root, os.str());

                os.str("");
                os << "Message " << ++i;
                LOG4CXX_WARN(logger, os.str());
                LOG4CXX_WARN(root, os.str());

                os.str("");
                os << "Message " << ++i;
                LOG4CXX_ERROR(logger, os.str());
                LOG4CXX_ERROR(root, os.str());

                os.str("");
                os << "Message " << ++i;
                LOG4CXX_FATAL(logger, os.str());
                LOG4CXX_FATAL(root, os.str());

        }
};

CPPUNIT_TEST_SUITE_REGISTRATION(DOMTestCase);

const File DOMTestCase::TEMP_A1(L"output/temp.A1");
const File DOMTestCase::TEMP_A2(L"output/temp.A2");
const File DOMTestCase::FILTERED_A1(L"output/filtered.A1");
const File DOMTestCase::FILTERED_A2(L"output/filtered.A2");

const File DOMTestCase::TEMP_A1_2(L"output/temp.A1.2");
const File DOMTestCase::TEMP_A2_2(L"output/temp.A2.2");
const File DOMTestCase::FILTERED_A1_2(L"output/filtered.A1.2");
const File DOMTestCase::FILTERED_A2_2(L"output/filtered.A2.2");


#endif //HAVE_XML
