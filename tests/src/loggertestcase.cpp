
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

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/logger.h>
#include <log4cxx/fileappender.h>
#include <log4cxx/appenderskeleton.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/level.h>
#include <log4cxx/hierarchy.h>
#include <log4cxx/spi/rootcategory.h>
#include <log4cxx/helpers/propertyresourcebundle.h>
#include "insertwide.h"
#include "testchar.h"
#include <log4cxx/helpers/locale.h>

using namespace log4cxx;
using namespace log4cxx::spi;
using namespace log4cxx::helpers;

class CountingAppender;
typedef helpers::ObjectPtrT<CountingAppender> CountingAppenderPtr;

class CountingAppender : public AppenderSkeleton
{
public:
        int counter;

        CountingAppender() : counter(0)
                {}

        void close()
                {}

        void append(const spi::LoggingEventPtr& event, Pool& p)
                { counter++; }

        bool requiresLayout() const
                { return true; }
};

class LoggerTestCase : public CppUnit::TestFixture
{
        CPPUNIT_TEST_SUITE(LoggerTestCase);
                CPPUNIT_TEST(testAppender1);
                CPPUNIT_TEST(testAppender2);
                CPPUNIT_TEST(testAdditivity1);
                CPPUNIT_TEST(testAdditivity2);
                CPPUNIT_TEST(testAdditivity3);
                CPPUNIT_TEST(testDisable1);
//    CPPUNIT_TEST(testRB1);
//    CPPUNIT_TEST(testRB2);  //TODO restore
//    CPPUNIT_TEST(testRB3);
                CPPUNIT_TEST(testExists);
                CPPUNIT_TEST(testHierarchy1);
        CPPUNIT_TEST_SUITE_END();

public:
        void setUp()
        {
        }

        void tearDown()
        {
                BasicConfigurator::resetConfiguration();
                a1 = 0;
                a2 = 0;
        logger = 0;
        }

        /**
        Add an appender and see if it can be retrieved.
        */
        void testAppender1()
        {
                logger = Logger::getLogger(LOG4CXX_TEST_STR("test"));
                a1 = new FileAppender();
                a1->setName(LOG4CXX_STR("testAppender1"));
                logger->addAppender(a1);

                AppenderList list = logger->getAllAppenders();
                AppenderPtr aHat = list.front();
                CPPUNIT_ASSERT_EQUAL(a1, aHat);
        }

        /**
        Add an appender X, Y, remove X and check if Y is the only
        remaining appender.
        */
        void testAppender2()
        {
                a1 = new FileAppender();
                a1->setName(LOG4CXX_STR("testAppender2.1"));
                a2 = new FileAppender();
                a2->setName(LOG4CXX_STR("testAppender2.2"));

                logger = Logger::getLogger(LOG4CXX_TEST_STR("test"));
                logger->addAppender(a1);
                logger->addAppender(a2);
                logger->removeAppender((LogString) LOG4CXX_STR("testAppender2.1"));

                AppenderList list = logger->getAllAppenders();
                AppenderPtr aHat = list.front();
                CPPUNIT_ASSERT_EQUAL(a2, aHat);
                CPPUNIT_ASSERT(list.size() == 1);
        }

        /**
        Test if LoggerPtr a.b inherits its appender from a.
        */
        void testAdditivity1()
        {
                LoggerPtr a = Logger::getLogger(LOG4CXX_TEST_STR("a"));
                LoggerPtr ab = Logger::getLogger(LOG4CXX_TEST_STR("a.b"));
                CountingAppenderPtr ca = new CountingAppender();
                a->addAppender(ca);

                CPPUNIT_ASSERT_EQUAL(ca->counter, 0);
                ab->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(ca->counter, 1);
                ab->info(MSG);
                CPPUNIT_ASSERT_EQUAL(ca->counter, 2);
                ab->warn(MSG);
                CPPUNIT_ASSERT_EQUAL(ca->counter, 3);
                ab->error(MSG);
                CPPUNIT_ASSERT_EQUAL(ca->counter, 4);
        }

        /**
        Test multiple additivity.
        */
        void testAdditivity2()
        {
                LoggerPtr a = Logger::getLogger(LOG4CXX_TEST_STR("a"));
                LoggerPtr ab = Logger::getLogger(LOG4CXX_TEST_STR("a.b"));
                LoggerPtr abc = Logger::getLogger(LOG4CXX_TEST_STR("a.b.c"));
                LoggerPtr x = Logger::getLogger(LOG4CXX_TEST_STR("x"));

                CountingAppenderPtr ca1 = new CountingAppender();
                CountingAppenderPtr ca2 = new CountingAppender();

                a->addAppender(ca1);
                abc->addAppender(ca2);

                CPPUNIT_ASSERT_EQUAL(ca1->counter, 0);
                CPPUNIT_ASSERT_EQUAL(ca2->counter, 0);

                ab->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(ca1->counter, 1);
                CPPUNIT_ASSERT_EQUAL(ca2->counter, 0);

                abc->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(ca1->counter, 2);
                CPPUNIT_ASSERT_EQUAL(ca2->counter, 1);

                x->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(ca1->counter, 2);
                CPPUNIT_ASSERT_EQUAL(ca2->counter, 1);
        }

        /**
        Test additivity flag.
        */
        void testAdditivity3()
        {
                LoggerPtr root = Logger::getRootLogger();
                LoggerPtr a = Logger::getLogger(LOG4CXX_TEST_STR("a"));
                LoggerPtr ab = Logger::getLogger(LOG4CXX_TEST_STR("a.b"));
                LoggerPtr abc = Logger::getLogger(LOG4CXX_TEST_STR("a.b.c"));
                LoggerPtr x = Logger::getLogger(LOG4CXX_TEST_STR("x"));

                CountingAppenderPtr caRoot = new CountingAppender();
                CountingAppenderPtr caA = new CountingAppender();
                CountingAppenderPtr caABC = new CountingAppender();

                root->addAppender(caRoot);
                a->addAppender(caA);
                abc->addAppender(caABC);

                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 0);
                CPPUNIT_ASSERT_EQUAL(caA->counter, 0);
                CPPUNIT_ASSERT_EQUAL(caABC->counter, 0);

                ab->setAdditivity(false);

                a->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 1);
                CPPUNIT_ASSERT_EQUAL(caA->counter, 1);
                CPPUNIT_ASSERT_EQUAL(caABC->counter, 0);

                ab->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 1);
                CPPUNIT_ASSERT_EQUAL(caA->counter, 1);
                CPPUNIT_ASSERT_EQUAL(caABC->counter, 0);

                abc->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 1);
                CPPUNIT_ASSERT_EQUAL(caA->counter, 1);
                CPPUNIT_ASSERT_EQUAL(caABC->counter, 1);
        }

        void testDisable1()
        {
                CountingAppenderPtr caRoot = new CountingAppender();
                LoggerPtr root = Logger::getRootLogger();
                root->addAppender(caRoot);

                LoggerRepositoryPtr h = LogManager::getLoggerRepository();

                //h.disableDebug();
                h->setThreshold(Level::INFO);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 0);

                root->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 0);
                root->info(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 1);
                root->log(Level::WARN, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 2);
                root->warn(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 3);

                //h.disableInfo();
                h->setThreshold(Level::WARN);
                root->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 3);
                root->info(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 3);
                root->log(Level::WARN, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 4);
                root->error(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 5);
                root->log(Level::ERROR, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);

                //h.disableAll();
                h->setThreshold(Level::OFF);
                root->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->info(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->log(Level::WARN, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->error(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->log(Level::FATAL, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->log(Level::FATAL, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);

                //h.disable(Level::getFatalLevel());
                h->setThreshold(Level::OFF);
                root->debug(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->info(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->log(Level::WARN, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->error(MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->log(Level::WARN, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
                root->log(Level::FATAL, MSG);
                CPPUNIT_ASSERT_EQUAL(caRoot->counter, 6);
        }


        ResourceBundlePtr getBundle(const LogString& lang, const LogString& region)
        {
             Locale l(lang, region);
             ResourceBundlePtr bundle(
                 PropertyResourceBundle::getBundle(LOG4CXX_STR("L7D"),l));
             CPPUNIT_ASSERT(bundle != 0);
             return bundle;
        }

        void testRB1()
        {
                ResourceBundlePtr rbUS(getBundle(LOG4CXX_STR("en"), LOG4CXX_STR("US")));
                ResourceBundlePtr rbFR(getBundle(LOG4CXX_STR("fr"), LOG4CXX_STR("FR")));
                ResourceBundlePtr rbCH(getBundle(LOG4CXX_STR("fr"), LOG4CXX_STR("CH")));

                LoggerPtr root = Logger::getRootLogger();
                root->setResourceBundle(rbUS);

                ResourceBundlePtr t = root->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);

                LoggerPtr x = Logger::getLogger(LOG4CXX_TEST_STR("x"));
                LoggerPtr x_y = Logger::getLogger(LOG4CXX_TEST_STR("x.y"));
                LoggerPtr x_y_z = Logger::getLogger(LOG4CXX_TEST_STR("x.y.z"));

                t = x->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);
                t = x_y->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);
                t = x_y_z->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);
        }

        void testRB2()
        {
                LoggerPtr root = Logger::getRootLogger();
                ResourceBundlePtr rbUS(getBundle(LOG4CXX_STR("en"), LOG4CXX_STR("US")));
                ResourceBundlePtr rbFR(getBundle(LOG4CXX_STR("fr"), LOG4CXX_STR("FR")));
                ResourceBundlePtr rbCH(getBundle(LOG4CXX_STR("fr"), LOG4CXX_STR("CH")));

                root->setResourceBundle(rbUS);

                ResourceBundlePtr t = root->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);

                LoggerPtr x = Logger::getLogger(LOG4CXX_TEST_STR("x"));
                LoggerPtr x_y = Logger::getLogger(LOG4CXX_TEST_STR("x.y"));
                LoggerPtr x_y_z = Logger::getLogger(LOG4CXX_TEST_STR("x.y.z"));

                x_y->setResourceBundle(rbFR);
                t = x->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);
                t = x_y->getResourceBundle();
                CPPUNIT_ASSERT(t == rbFR);
                t = x_y_z->getResourceBundle();
                CPPUNIT_ASSERT(t == rbFR);
        }

        void testRB3()
        {
                ResourceBundlePtr rbUS(getBundle(LOG4CXX_STR("en"), LOG4CXX_STR("US")));
                ResourceBundlePtr rbFR(getBundle(LOG4CXX_STR("fr"), LOG4CXX_STR("FR")));
                ResourceBundlePtr rbCH(getBundle(LOG4CXX_STR("fr"), LOG4CXX_STR("CH")));

                LoggerPtr root = Logger::getRootLogger();
                root->setResourceBundle(rbUS);

                ResourceBundlePtr t = root->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);

                LoggerPtr x = Logger::getLogger(LOG4CXX_TEST_STR("x"));
                LoggerPtr x_y = Logger::getLogger(LOG4CXX_TEST_STR("x.y"));
                LoggerPtr x_y_z = Logger::getLogger(LOG4CXX_TEST_STR("x.y.z"));

                x_y->setResourceBundle(rbFR);
                x_y_z->setResourceBundle(rbCH);
                t = x->getResourceBundle();
                CPPUNIT_ASSERT(t == rbUS);
                t = x_y->getResourceBundle();
                CPPUNIT_ASSERT(t == rbFR);
                t = x_y_z->getResourceBundle();
                CPPUNIT_ASSERT(t == rbCH);
        }

        void testExists()
        {
                LoggerPtr a = Logger::getLogger(LOG4CXX_TEST_STR("a"));
                LoggerPtr a_b = Logger::getLogger(LOG4CXX_TEST_STR("a.b"));
                LoggerPtr a_b_c = Logger::getLogger(LOG4CXX_TEST_STR("a.b.c"));

                LoggerPtr t;
                t = LogManager::exists(LOG4CXX_TEST_STR("xx"));
                CPPUNIT_ASSERT(t == 0);
                t = LogManager::exists(LOG4CXX_TEST_STR("a"));
                CPPUNIT_ASSERT_EQUAL(a, t);
                t = LogManager::exists(LOG4CXX_TEST_STR("a.b"));
                CPPUNIT_ASSERT_EQUAL(a_b, t);
                t = LogManager::exists(LOG4CXX_TEST_STR("a.b.c"));
                CPPUNIT_ASSERT_EQUAL(a_b_c, t);
        }

        void testHierarchy1()
        {
                LoggerPtr root(new RootCategory(Level::ERROR));
                LoggerRepositoryPtr h = new Hierarchy(root);
                LoggerPtr a0 = h->getLogger(LOG4CXX_STR("a"));
                CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("a"), a0->getName());
                CPPUNIT_ASSERT(a0->getLevel() == 0);
                CPPUNIT_ASSERT(Level::ERROR == a0->getEffectiveLevel());

                LoggerPtr a1 = h->getLogger(LOG4CXX_STR("a"));
                CPPUNIT_ASSERT_EQUAL(a0, a1);
        }

protected:
        static LogString MSG;
        LoggerPtr logger;
        AppenderPtr a1;
        AppenderPtr a2;
};

LogString LoggerTestCase::MSG(LOG4CXX_STR("M"));

CPPUNIT_TEST_SUITE_REGISTRATION(LoggerTestCase);
