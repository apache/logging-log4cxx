/*
 * Copyright 1999,2005 The Apache Software Foundation.
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

#include "../util/compare.h"
#include "../insertwide.h"
#include <apr_time.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/rolling/fixedwindowrollingpolicy.h>
#include <log4cxx/rolling/sizebasedtriggeringpolicy.h>
#include <log4cxx/filter/levelrangefilter.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/logger.h>
#include <log4cxx/propertyconfigurator.h>
#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/helpers/stringhelper.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/fileoutputstream.h>


  using namespace log4cxx;
  using namespace log4cxx::xml;
  using namespace log4cxx::filter;
  using namespace log4cxx::helpers;
  using namespace log4cxx::rolling;

/**
 *
 * Do not forget to call activateOptions when configuring programatically.
 *
 * @author Ceki G&uuml;lc&uuml;
 *
 */
 class SizeBasedRollingTest  : public CppUnit::TestFixture  {
   CPPUNIT_TEST_SUITE(SizeBasedRollingTest);
           CPPUNIT_TEST(test1);
           CPPUNIT_TEST(test2);
//           TODO: Compression not yet implemented
//           CPPUNIT_TEST(test3);
           CPPUNIT_TEST(test4);
           CPPUNIT_TEST(test5);
   CPPUNIT_TEST_SUITE_END();

   LoggerPtr root;
   LoggerPtr logger;

 public:
  void setUp() {
    PatternLayoutPtr layout(new PatternLayout(LOG4CXX_STR("%d %level %c -%m%n")));
    AppenderPtr ca(new ConsoleAppender(layout));
    ca->setName(LOG4CXX_STR("CONSOLE"));
    root = Logger::getRootLogger();
    root->addAppender(ca);
    logger = Logger::getLogger("org.apache.log4j.rolling.SizeBasedRollingTest");
  }

  void tearDown() {
    LogManager::shutdown();
  }

void common(LoggerPtr& logger, int sleep) {
  char msg[] = { 'H', 'e', 'l', 'l', 'o', '-', '-', '-', 'N', 0 };

// Write exactly 10 bytes with each log
for (int i = 0; i < 25; i++) {
  if (i < 10) {
    msg[8] = '0' + i;
  } else if (i < 100) {
    msg[7] = '0' + i / 10;
    msg[8] = '0' + i % 10;
  }
  LOG4CXX_DEBUG(logger, msg);
}
}
/**
 * Tests that the lack of an explicit active file will use the
 * low index as the active file.
 *
 */
void test1() {
    PatternLayoutPtr layout = new PatternLayout(LOG4CXX_STR("%m\n"));
    RollingFileAppenderPtr rfa = new RollingFileAppender();
    rfa->setName(LOG4CXX_STR("ROLLING"));
    rfa->setAppend(false);
    rfa->setLayout(layout);

    FixedWindowRollingPolicyPtr swrp = new FixedWindowRollingPolicy();
    SizeBasedTriggeringPolicyPtr sbtp = new SizeBasedTriggeringPolicy();

    sbtp->setMaxFileSize(100);
    swrp->setMinIndex(0);

    swrp->setFileNamePattern(LOG4CXX_STR("output/sizeBased-test1.%i"));
    Pool p;
    swrp->activateOptions(p);

    rfa->setRollingPolicy(swrp);
    rfa->setTriggeringPolicy(sbtp);
    rfa->activateOptions(p);
    root->addAppender(rfa);


    common(logger, 0);

    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test1.0").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test1.1").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test1.2").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test1.0"),
     File("witness/rolling/sbr-test2.log")));
    CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test1.1"),
     File("witness/rolling/sbr-test2.0")));
    CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test1.2"),
     File("witness/rolling/sbr-test2.1")));
}

/**
 * Test basic rolling functionality with explicit setting of FileAppender.file.
 */
void test2() {
PatternLayoutPtr layout = new PatternLayout(LOG4CXX_STR("%m\n"));
RollingFileAppenderPtr rfa = new RollingFileAppender();
rfa->setName(LOG4CXX_STR("ROLLING"));
rfa->setAppend(false);
rfa->setLayout(layout);
rfa->setFile(LOG4CXX_STR("output/sizeBased-test2.log"));

FixedWindowRollingPolicyPtr swrp = new FixedWindowRollingPolicy();
SizeBasedTriggeringPolicyPtr sbtp = new SizeBasedTriggeringPolicy();

sbtp->setMaxFileSize(100);
swrp->setMinIndex(0);

swrp->setFileNamePattern(LOG4CXX_STR("output/sizeBased-test2.%i"));
Pool p;
swrp->activateOptions(p);

rfa->setRollingPolicy(swrp);
rfa->setTriggeringPolicy(sbtp);
rfa->activateOptions(p);
root->addAppender(rfa);

common(logger, 0);

CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test2.log").exists(p));
CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test2.0").exists(p));
CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test2.1").exists(p));

CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test2.log"),
 File("witness/rolling/sbr-test2.log")));
CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test2.0"),
 File("witness/rolling/sbr-test2.0")));
CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test2.1"),
 File("witness/rolling/sbr-test2.1")));
}

/**
 * Same as testBasic but also with GZ compression.
 */
void test3() {
 PatternLayoutPtr layout = new PatternLayout(LOG4CXX_STR("%m\n"));
 RollingFileAppenderPtr rfa = new RollingFileAppender();
 rfa->setAppend(false);
 rfa->setLayout(layout);

 FixedWindowRollingPolicyPtr  fwrp = new FixedWindowRollingPolicy();
 SizeBasedTriggeringPolicyPtr sbtp = new SizeBasedTriggeringPolicy();

 sbtp->setMaxFileSize(100);
 fwrp->setMinIndex(0);
 rfa->setFile(LOG4CXX_STR("output/sbr-test3.log"));
 fwrp->setFileNamePattern(LOG4CXX_STR("output/sbr-test3.%i.gz"));
 Pool p;
 fwrp->activateOptions(p);
 rfa->setRollingPolicy(fwrp);
 rfa->setTriggeringPolicy(sbtp);
 rfa->activateOptions(p);
 root->addAppender(rfa);

 common(logger, 100);

CPPUNIT_ASSERT_EQUAL(true, File("output/sbr-test3.log").exists(p));
CPPUNIT_ASSERT_EQUAL(true, File("output/sbr-test3.0.gz").exists(p));
CPPUNIT_ASSERT_EQUAL(true, File("output/sbr-test3.1.gz").exists(p));

CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sbr-test3.log"),  File("witness/rolling/sbr-test3.log")));
CPPUNIT_ASSERT_EQUAL(true, Compare::gzCompare(File("output/sbr-test3.0.gz"), File("witness/rolling/sbr-test3.0.gz")));
CPPUNIT_ASSERT_EQUAL(true, Compare::gzCompare(File("output/sbr-test3.1.gz"), File("witness/rolling/sbr-test3.1.gz")));
}

/**
 * Test basic rolling functionality with bogus path in file name pattern.
 */
void test4() {
PatternLayoutPtr layout = new PatternLayout(LOG4CXX_STR("%m\n"));
RollingFileAppenderPtr rfa = new RollingFileAppender();
rfa->setName(LOG4CXX_STR("ROLLING"));
rfa->setAppend(false);
rfa->setLayout(layout);
rfa->setFile(LOG4CXX_STR("output/sizeBased-test4.log"));

FixedWindowRollingPolicyPtr swrp = new FixedWindowRollingPolicy();
SizeBasedTriggeringPolicyPtr sbtp = new SizeBasedTriggeringPolicy();

sbtp->setMaxFileSize(100);
swrp->setMinIndex(0);

//
//   test4 directory should not exists.  Should cause all rollover attempts to fail.
//
swrp->setFileNamePattern(LOG4CXX_STR("output/test4/sizeBased-test4.%i"));
Pool p;
swrp->activateOptions(p);

rfa->setRollingPolicy(swrp);
rfa->setTriggeringPolicy(sbtp);
rfa->activateOptions(p);
root->addAppender(rfa);

common(logger, 0);

CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test4.log").exists(p));

CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test4.log"),
 File("witness/rolling/sbr-test4.log")));
}

/**
 * Checking handling of rename failures due to other access
 * to the indexed files.
 */
void test5()  {
PatternLayoutPtr layout = new PatternLayout(LOG4CXX_STR("%m\n"));
RollingFileAppenderPtr rfa = new RollingFileAppender();
rfa->setName(LOG4CXX_STR("ROLLING"));
rfa->setAppend(false);
rfa->setLayout(layout);
rfa->setFile(LOG4CXX_STR("output/sizeBased-test5.log"));

FixedWindowRollingPolicyPtr swrp = new FixedWindowRollingPolicy();
SizeBasedTriggeringPolicyPtr sbtp = new SizeBasedTriggeringPolicy();

sbtp->setMaxFileSize(100);
swrp->setMinIndex(0);

swrp->setFileNamePattern(LOG4CXX_STR("output/sizeBased-test5.%i"));
Pool p;
swrp->activateOptions(p);

rfa->setRollingPolicy(swrp);
rfa->setTriggeringPolicy(sbtp);
rfa->activateOptions(p);
root->addAppender(rfa);

//
//   put stray file about locked file
FileOutputStream os1(LOG4CXX_STR("output/sizeBased-test5.1"), false);
os1.close(p);


FileOutputStream os0(LOG4CXX_STR("output/sizeBased-test5.0"), false);

common(logger, 0);

os0.close(p);

if (File("output/sizeBased-test5.3").exists(p)) {
    //
    //    looks like platform where open files can be renamed
    //
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.log").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.0").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.1").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.2").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.3").exists(p));

    CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test5.log"),
     File("witness/rolling/sbr-test2.log")));
    CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test5.0"),
     File("witness/rolling/sbr-test2.0")));
    CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test5.1"),
     File("witness/rolling/sbr-test2.1")));

} else {
    //
    //  rollover attempts should all fail
    //    so initial log file should have all log content
    //    open file should be unaffected
    //    stray file should have only been moved one slot.
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.log").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.0").exists(p));
    CPPUNIT_ASSERT_EQUAL(true, File("output/sizeBased-test5.2").exists(p));

    CPPUNIT_ASSERT_EQUAL(true, Compare::compare(File("output/sizeBased-test5.log"),
        File("witness/rolling/sbr-test4.log")));
}
}


};


CPPUNIT_TEST_SUITE_REGISTRATION(SizeBasedRollingTest);
