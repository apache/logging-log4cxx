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

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/logger.h>
#include <log4cxx/xml/xmllayout.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/mdc.h>

#include "../util/transformer.h"
#include "../util/compare.h"
#include "../util/xmltimestampfilter.h"
#include "../util/xmllineattributefilter.h"
#include "../util/xmlthreadfilter.h"
#include "../util/filenamefilter.h"
#include <iostream>
#include <log4cxx/helpers/stringhelper.h>
#include "../testchar.h"
#include <log4cxx/spi/loggerrepository.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;

#if _MSC_VER < 1300
#undef __LOG4CXX_FUNC__
#define __LOG4CXX_FUNC__ "X::X()"
#endif

class X
{
public:
        X()
        {
                LoggerPtr logger =
                        Logger::getLogger(LOG4CXX_TEST_STR("org.apache.log4j.xml.XMLLayoutTestCase$X"));
                LOG4CXX_INFO(logger, LOG4CXX_TEST_STR("in X() constructor"));
        }
};



class XMLLayoutTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(XMLLayoutTestCase);
                CPPUNIT_TEST(basic);
                CPPUNIT_TEST(locationInfo);
                CPPUNIT_TEST(testCDATA);
                CPPUNIT_TEST(testNULL);
                CPPUNIT_TEST(testMDC);
        CPPUNIT_TEST_SUITE_END();

        LoggerPtr root;
        LoggerPtr logger;

public:
        void setUp()
        {
                root = Logger::getRootLogger();
                logger = Logger::getLogger(LOG4CXX_TEST_STR("org.apache.log4j.xml.XMLLayoutTestCase"));
        }

        void tearDown()
        {
                logger->getLoggerRepository()->resetConfiguration();
        }

        void basic()
        {
                XMLLayoutPtr xmlLayout = new XMLLayout();
                AppenderPtr appender(new FileAppender(xmlLayout, TEMP, false));
                root->addAppender(appender);
                common();

                XMLTimestampFilter xmlTimestampFilter;
                XMLThreadFilter xmlThreadFilter;

                std::vector<Filter *> filters;
                filters.push_back(&xmlTimestampFilter);
                filters.push_back(&xmlThreadFilter);

                try
                {
                        Transformer::transform(TEMP, FILTERED, filters);
                }
                catch(UnexpectedFormatException& e)
                {
                        std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                CPPUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/xmlLayout.1")));
        }

        void locationInfo()
        {
                XMLLayoutPtr xmlLayout = new XMLLayout();
                xmlLayout->setLocationInfo(true);
                root->addAppender(new FileAppender(xmlLayout, TEMP, false));
                common();

                XMLTimestampFilter xmlTimestampFilter;
                XMLThreadFilter xmlThreadFilter;
                FilenameFilter xmlFilenameFilter(__FILE__, "xmllayouttestcase.cpp");
                Filter line2XX("[23][0-9][0-9]", "X");
                Filter line5X("53", "X");

                std::vector<Filter *> filters;
                filters.push_back(&xmlFilenameFilter);
                filters.push_back(&xmlTimestampFilter);

                filters.push_back(&xmlThreadFilter);
                filters.push_back(&line2XX);
                filters.push_back(&line5X);

                try
                {
                        Transformer::transform(TEMP, FILTERED, filters);
                }
                catch(UnexpectedFormatException& e)
                {
                        std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                CPPUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/xmlLayout.2")));
        }

#if _MSC_VER < 1300
#undef __LOG4CXX_FUNC__
#define __LOG4CXX_FUNC__ "void XMLLayoutTestCase::testCDATA()"
#endif

        void testCDATA()
        {
                XMLLayoutPtr xmlLayout = new XMLLayout();
                xmlLayout->setLocationInfo(true);
                FileAppenderPtr appender(new FileAppender(xmlLayout, TEMP, false));
                root->addAppender(appender);

                LOG4CXX_DEBUG(logger,
                        LOG4CXX_TEST_STR("Message with embedded <![CDATA[<hello>hi</hello>]]>."));

                XMLTimestampFilter xmlTimestampFilter;
                XMLThreadFilter xmlThreadFilter;
                FilenameFilter xmlFilenameFilter(__FILE__, "xmllayouttestcase.cpp");
                Filter line1xx("1[0-9][0-9]", "X");

                std::vector<Filter *> filters;
                filters.push_back(&xmlFilenameFilter);
                filters.push_back(&xmlTimestampFilter);
                filters.push_back(&xmlThreadFilter);
                filters.push_back(&line1xx);

                try
                {
                        Transformer::transform(TEMP, FILTERED, filters);
                }
                catch(UnexpectedFormatException& e)
                {
                        std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                CPPUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/xmlLayout.3")));
        }

        void testNULL()
        {
                XMLLayoutPtr xmlLayout = new XMLLayout();
                FileAppenderPtr appender(new FileAppender(xmlLayout, TEMP, false));
                root->addAppender(appender);

                LOG4CXX_DEBUG(logger, LOG4CXX_TEST_STR("hi"));
                LOG4CXX_DEBUG(logger, LOG4CXX_TEST_STR(""));

                XMLTimestampFilter xmlTimestampFilter;
                XMLThreadFilter xmlThreadFilter;

                std::vector<Filter *> filters;
                filters.push_back(&xmlTimestampFilter);
                filters.push_back(&xmlThreadFilter);

                try
                {
                        Transformer::transform(TEMP, FILTERED, filters);
                }
                catch(UnexpectedFormatException& e)
                {
                        std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                CPPUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/xmlLayout.null")));
        }

        void testMDC()
        {
                XMLLayoutPtr xmlLayout = new XMLLayout();
                FileAppenderPtr appender(new FileAppender(xmlLayout, TEMP, false));
                root->addAppender(appender);

                MDC::clear();
                MDC::put(LOG4CXX_TEST_STR("key1"), LOG4CXX_TEST_STR("val1"));
                MDC::put(LOG4CXX_TEST_STR("key2"), LOG4CXX_TEST_STR("val2"));

                LOG4CXX_DEBUG(logger, LOG4CXX_TEST_STR("Hello"));

                MDC::clear();

                XMLTimestampFilter xmlTimestampFilter;
                XMLThreadFilter xmlThreadFilter;

                std::vector<Filter *> filters;
                filters.push_back(&xmlTimestampFilter);
                filters.push_back(&xmlThreadFilter);

                try
                {
                        Transformer::transform(TEMP, FILTERED, filters);
                }
                catch(UnexpectedFormatException& e)
                {
                        std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                CPPUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/xmlLayout.mdc.1")));
        }

        // not incuded in the tests for the moment !
        void holdTestMDCEscaped()
        {
                XMLLayoutPtr xmlLayout = new XMLLayout();
                FileAppenderPtr appender(new FileAppender(xmlLayout, TEMP, false));
                root->addAppender(appender);

                MDC::clear();
                MDC::put(LOG4CXX_TEST_STR("blahAttribute"), LOG4CXX_TEST_STR("<blah value=\"blah\">"));
                MDC::put(LOG4CXX_TEST_STR("<blahKey value=\"blah\"/>"), LOG4CXX_TEST_STR("blahValue"));

                LOG4CXX_DEBUG(logger, LOG4CXX_TEST_STR("Hello"));

                MDC::clear();

                XMLTimestampFilter xmlTimestampFilter;
                XMLThreadFilter xmlThreadFilter;

                std::vector<Filter *> filters;
                filters.push_back(&xmlTimestampFilter);
                filters.push_back(&xmlThreadFilter);

                try
                {
                        Transformer::transform(TEMP, FILTERED, filters);
                }
                catch(UnexpectedFormatException& e)
                {
                        std::cout << "UnexpectedFormatException :" << e.what() << std::endl;
                        throw;
                }

                CPPUNIT_ASSERT(Compare::compare(FILTERED, LOG4CXX_FILE("witness/xmlLayout.mdc.2")));
        }


#if _MSC_VER < 1300
#undef __LOG4CXX_FUNC__
#define __LOG4CXX_FUNC__ "void XMLLayoutTestCase::common()"
#endif

        void common()
        {
                int i = -1;
                X x;

                Pool p;
                LogString msg(LOG4CXX_STR("Message "));

                LOG4CXX_DEBUG(logger, msg + StringHelper::toString(++i, p));
                LOG4CXX_DEBUG(root, msg + StringHelper::toString(i, p));

                LOG4CXX_INFO(logger, msg + StringHelper::toString(++i, p));
                LOG4CXX_INFO(root, msg + StringHelper::toString(i,p));

                LOG4CXX_WARN(logger, msg + StringHelper::toString(++i, p));
                LOG4CXX_WARN(root, msg + StringHelper::toString(i, p));

                LOG4CXX_ERROR(logger, msg + StringHelper::toString(++i, p));
                LOG4CXX_ERROR(root, msg + StringHelper::toString(i, p));

                LOG4CXX_FATAL(logger, msg + StringHelper::toString(++i, p));
                LOG4CXX_FATAL(root, msg + StringHelper::toString(i, p));
        }
        private:
        static const File TEMP;
        static const File FILTERED;
};

const File XMLLayoutTestCase::TEMP("output/temp");
const File XMLLayoutTestCase::FILTERED("output/filtered");

CPPUNIT_TEST_SUITE_REGISTRATION(XMLLayoutTestCase);
