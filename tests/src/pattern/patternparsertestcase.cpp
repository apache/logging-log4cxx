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

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <log4cxx/logger.h>
#include <log4cxx/spi/loggingevent.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/level.h>

#include "num343patternconverter.h"
#include "../testchar.h"
#include "../insertwide.h"
#include <log4cxx/spi/loggerrepository.h>
#include <log4cxx/helpers/patternparser.h>
#include <log4cxx/helpers/patternconverter.h>
#include <log4cxx/helpers/relativetimedateformat.h>
#include <log4cxx/helpers/simpledateformat.h>

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::spi;
using namespace log4cxx::pattern;


class PatternParserTestCase : public CppUnit::TestFixture
{
   CPPUNIT_TEST_SUITE(PatternParserTestCase);
      CPPUNIT_TEST(testNewWord);
      CPPUNIT_TEST(testNewWord2);
      CPPUNIT_TEST(testBogusWord1);
      CPPUNIT_TEST(testBogusWord2);
      CPPUNIT_TEST(testBasic1);
      CPPUNIT_TEST(testBasic2);
      CPPUNIT_TEST(testMultiOption);
   CPPUNIT_TEST_SUITE_END();

   LoggerPtr logger;
   LoggingEventPtr event;

public:
   void setUp()
   {
      logger = Logger::getLogger(LOG4CXX_TEST_STR("org.foobar"));

      event = new LoggingEvent(
         logger, Level::INFO, LOG4CXX_STR("msg 1"), LOG4CXX_LOCATION);
   }

   void tearDown()
   {
      logger->getLoggerRepository()->resetConfiguration();
   }

   void convert(LoggingEventPtr& event,
      PatternConverterPtr& head,
      Pool& p,
      LogString& dst) {
     PatternConverterPtr c(head);

     while (c != NULL) {
       c->format(dst, event, p);
       c = c->next;
     }
   }


   void testNewWord()  {
     PatternParser patternParser(LOG4CXX_STR("%z343"));
     PatternParser::PatternConverterMap ruleRegistry;
     LogString name(LOG4CXX_STR("z343"));
     ruleRegistry.insert(
        PatternParser::PatternConverterMap::value_type(name,
           LOG4CXX_STR("org.apache.log4j.pattern.Num343PatternConverter")));

     patternParser.setConverterRegistry(ruleRegistry);

     PatternConverterPtr head(patternParser.parse());

     Pool p;
     LogString result;
     convert(event, head, p, result);
     CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("343"), result);
   }


   /* Test whether words starting with the letter 'n' are treated differently,
    * which was previously the case by mistake.
    */
   void testNewWord2()  {
     PatternParser patternParser(LOG4CXX_STR("%n343"));

     PatternParser::PatternConverterMap ruleRegistry;
     LogString name(LOG4CXX_STR("n343"));
     ruleRegistry.insert(
        PatternParser::PatternConverterMap::value_type(name,
           LOG4CXX_STR("org.apache.log4j.pattern.Num343PatternConverter")));

     patternParser.setConverterRegistry(ruleRegistry);

     PatternConverterPtr head(patternParser.parse());

     Pool p;
     LogString result;
     convert(event, head, p, result);
     CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("343"), result);
   }

   void testBogusWord1()  {
     PatternParser patternParser(LOG4CXX_STR("%, foobar"));
     PatternConverterPtr head(patternParser.parse());

     Pool p;
     LogString result;
     convert(event, head, p, result);

     CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("%, foobar"), result);
   }

   void testBogusWord2()  {
     PatternParser patternParser(LOG4CXX_STR("xyz %, foobar"));
     PatternConverterPtr head = patternParser.parse();

     Pool p;
     LogString result;
     convert(event, head, p, result);


     CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("xyz %, foobar"), result);
   }

   void testBasic1()  {
     PatternParser patternParser(LOG4CXX_STR("hello %-5level - %m%n"));
     PatternConverterPtr head = patternParser.parse();

     Pool p;
     LogString result;
     convert(event, head, p, result);

     CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("hello INFO  - msg 1") LOG4CXX_EOL, result);
   }

   void testBasic2()  {
     PatternParser patternParser(
       LOG4CXX_STR("%relative %-5level [%thread] %logger - %m%n"));
     PatternConverterPtr head = patternParser.parse();

     Pool pool;
     LogString result;
     convert(event, head, pool, result);


     RelativeTimeDateFormat relativeFormat;
     LogString expected;
     relativeFormat.format(expected, event->getTimeStamp(), pool);

     expected.append(LOG4CXX_STR(" INFO  ["));
     expected.append(event->getThreadName());
     expected.append(LOG4CXX_STR("] "));
     expected.append(logger->getName());
     expected.append(LOG4CXX_STR(" - msg 1") LOG4CXX_EOL);

     CPPUNIT_ASSERT_EQUAL(expected, result);
   }

   void testMultiOption()  {
     PatternParser patternParser
       (LOG4CXX_STR("%d{HH:mm:ss}{GMT} %d{HH:mm:ss} %c  - %m"));
     PatternConverterPtr head = patternParser.parse();

     Pool pool;
     LogString result;
     convert(event, head, pool, result);

     SimpleDateFormat dateFormat(LOG4CXX_STR("HH:mm:ss"));
     LogString localTime;
     dateFormat.format(localTime, event->getTimeStamp(), pool);

     dateFormat.setTimeZone(TimeZone::getGMT());
     LogString utcTime;
     dateFormat.format(utcTime, event->getTimeStamp(), pool);

     LogString buf(utcTime);
     buf.append(1, LOG4CXX_STR(' '));
     buf.append(localTime);
     buf.append(LOG4CXX_STR(" org.foobar  - msg 1"));
     CPPUNIT_ASSERT_EQUAL(buf, result);

   }

};

CPPUNIT_TEST_SUITE_REGISTRATION(PatternParserTestCase);
