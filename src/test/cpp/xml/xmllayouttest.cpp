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
#include <apr_xml.h>
#include <log4cxx/ndc.h>
#include <log4cxx/mdc.h>
#include "../xml/xlevel.h"
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/transcoder.h>


using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;
using namespace log4cxx::spi;

#if defined(__LOG4CXX_FUNC__)
#undef __LOG4CXX_FUNC__
#define __LOG4CXX_FUNC__ "X::X()"
#else
#error __LOG4CXX_FUNC__ expected to be defined
#endif
/**
 * Test for XMLLayout.
 *
 */
class XMLLayoutTest : public CppUnit::TestFixture {
        CPPUNIT_TEST_SUITE(XMLLayoutTest);
                CPPUNIT_TEST(testGetContentType);
                CPPUNIT_TEST(testIgnoresThrowable);
                CPPUNIT_TEST(testGetHeader);
                CPPUNIT_TEST(testGetFooter);
                CPPUNIT_TEST(testFormat);
                CPPUNIT_TEST(testFormatWithNDC);
                CPPUNIT_TEST(testGetSetLocationInfo);
                CPPUNIT_TEST(testActivateOptions);
                CPPUNIT_TEST(testProblemCharacters);
                CPPUNIT_TEST(testNDCWithCDATA);
        CPPUNIT_TEST_SUITE_END();

#if 0
  /**
   * Construct new instance of XMLLayoutTest.
   *
   * @param testName test name.
   */
  public XMLLayoutTest(final String testName) {
    super(testName, "text/plain", false, null, null);
  }
#endif  
  
public:  
    /**
     * Clear MDC and NDC before test.
     */
  void setUp() {
      NDC::clear();
      MDC::clear();
  }

    /**
     * Clear MDC and NDC after test.
     */
  void tearDown() {
      setUp();
  }


public:
  /**
   * Tests getContentType.
   */
  void testGetContentType() {
    LogString expected(LOG4CXX_STR("text/plain"));
    LogString actual(XMLLayout().getContentType());
    CPPUNIT_ASSERT(expected == actual);
  }

  /**
   * Tests ignoresThrowable.
   */
  void testIgnoresThrowable() {
    CPPUNIT_ASSERT_EQUAL(false, XMLLayout().ignoresThrowable());
  }

  /**
   * Tests getHeader.
   */
  void testGetHeader() {
    Pool p;
    LogString header;
    XMLLayout().appendHeader(header, p);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, header.size());
  }

  /**
   * Tests getFooter.
   */
  void testGetFooter() {
    Pool p;
    LogString footer;
    XMLLayout().appendFooter(footer, p);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, footer.size());
  }

private:
  /**
   * Parses the string as the body of an XML document and returns the document element.
   * @param source source string.
   * @return document element.
   * @throws Exception if parser can not be constructed or source is not a valid XML document.
   */
  static apr_xml_elem* parse(const LogString& source, Pool& p) {
    char backing[3000];
    ByteBuffer buf(backing, sizeof(backing));
    CharsetEncoderPtr encoder(CharsetEncoder::getUTF8Encoder());
    LogString header(LOG4CXX_STR("<log4j:eventSet xmlns:log4j='http://jakarta.apache.org/log4j/'>"));
    LogString::const_iterator iter(header.begin());
    encoder->encode(header, iter, buf);
    CPPUNIT_ASSERT(iter == header.end());
    iter = source.begin();
    encoder->encode(source, iter, buf);
    CPPUNIT_ASSERT(iter == source.end());
    LogString footer(LOG4CXX_STR("</log4j:eventSet>"));
    iter = footer.begin();
    encoder->encode(footer, iter, buf);
    buf.flip();
    apr_pool_t* apr_pool = (apr_pool_t*) p.getAPRPool();
    apr_xml_parser* parser = apr_xml_parser_create(apr_pool);
    CPPUNIT_ASSERT(parser != 0);
    apr_status_t stat = apr_xml_parser_feed(parser, buf.data(), buf.remaining());
    CPPUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
    apr_xml_doc* doc = 0;
    stat = apr_xml_parser_done(parser, &doc);
    CPPUNIT_ASSERT(doc != 0);
    apr_xml_elem* eventSet = doc->root;
    CPPUNIT_ASSERT(eventSet != 0);
    apr_xml_elem* event = eventSet->first_child;
    CPPUNIT_ASSERT(event != 0);
    return event;    
  }

  std::string getAttribute(apr_xml_elem* elem, const char* attrName) {
     for(apr_xml_attr* attr = elem->attr;
         attr != NULL;
         attr = attr->next) {
         if (strcmp(attr->name, attrName) == 0) {
            return attr->value;
         }
     }
     return "";
  }

  std::string getText(apr_xml_elem* elem) {
    std::string dMessage;
        for(apr_text* t = elem->first_cdata.first;
            t != NULL;
            t = t->next) {
            dMessage.append(t->text);
        }
    return dMessage;
  }
  /**
   * Checks a log4j:event element against expectations.
   * @param element element, may not be null.
   * @param event event, may not be null.
   */
  void checkEventElement(
    apr_xml_elem* element, LoggingEventPtr& event) {
    std::string tagName("event");
    CPPUNIT_ASSERT_EQUAL(tagName, (std::string) element->name);
    LOG4CXX_ENCODE_CHAR(cLoggerName, event->getLoggerName());
    CPPUNIT_ASSERT_EQUAL(cLoggerName, getAttribute(element, "logger"));
    LOG4CXX_ENCODE_CHAR(cLevelName, event->getLevel()->toString());
    CPPUNIT_ASSERT_EQUAL(cLevelName, getAttribute(element, "level"));
  }

  /**
   * Checks a log4j:message element against expectations.
   * @param element element, may not be null.
   * @param message expected message.
   */
  void checkMessageElement(
    apr_xml_elem* element, std::string message) {
    std::string tagName = "message";
    CPPUNIT_ASSERT_EQUAL(tagName, (std::string) element->name);
    CPPUNIT_ASSERT_EQUAL(message, getText(element));
  }

  /**
   * Checks a log4j:message element against expectations.
   * @param element element, may not be null.
   * @param message expected message.
   */
  void checkNDCElement(apr_xml_elem* element, std::string message) {
    std::string tagName = "NDC";
    CPPUNIT_ASSERT_EQUAL(tagName, (std::string) element->name);
    std::string dMessage = getText(element);
    CPPUNIT_ASSERT_EQUAL(message, dMessage);
  }


    /**
     * Checks a log4j:properties element against expectations.
     * @param element element, may not be null.
     * @param key key.
     * @param value value.
     */
    void checkPropertiesElement(
      apr_xml_elem* element, std::string key, std::string value) {
    std::string tagName = "properties";
    std::string dataTag = "data";
    int childNodeCount = 0;
    CPPUNIT_ASSERT_EQUAL(tagName, (std::string) element->name);
    for(apr_xml_elem* child = element->first_child;
        child != NULL;
        child = child->next) {
            CPPUNIT_ASSERT_EQUAL(dataTag, (std::string) child->name);
            CPPUNIT_ASSERT_EQUAL(key, getAttribute(child, "name"));
            CPPUNIT_ASSERT_EQUAL(value, getAttribute(child, "value"));
            childNodeCount++;        
    }
    CPPUNIT_ASSERT_EQUAL(1, childNodeCount);
    }

public:
  /**
   * Tests formatted results.
   * @throws Exception if parser can not be constructed or source is not a valid XML document.
   */
  void testFormat() {
    LoggerPtr logger = Logger::getLogger("org.apache.log4j.xml.XMLLayoutTest");
    LoggingEventPtr event =
      new LoggingEvent(
        logger, Level::getInfo(), LOG4CXX_STR("Hello, World"), LOG4CXX_LOCATION);
    Pool p;
    XMLLayout layout;
    LogString result;
    layout.format(result, event, p);
    apr_xml_elem* parsedResult = parse(result, p);
    checkEventElement(parsedResult, event);

    int childElementCount = 0;
    for (
      apr_xml_elem* node = parsedResult->first_child; 
      node != NULL;
      node = node->next) {
        childElementCount++;
        checkMessageElement(node, "Hello, World");
    }

    CPPUNIT_ASSERT_EQUAL(1, childElementCount);
  }


  /**
   * Tests formatted results with an exception.
   * @throws Exception if parser can not be constructed or source is not a valid XML document.
   */
  void testFormatWithNDC() {
    LoggerPtr logger = Logger::getLogger("org.apache.log4j.xml.XMLLayoutTest");
    NDC::push("NDC goes here");

    LoggingEventPtr event =
      new LoggingEvent(
        logger, Level::getInfo(), LOG4CXX_STR("Hello, World"), LOG4CXX_LOCATION);
    Pool p;
    XMLLayout layout;
    LogString result;
    layout.format(result, event, p);
    NDC::pop();

    apr_xml_elem* parsedResult = parse(result, p);
    checkEventElement(parsedResult, event);

    int childElementCount = 0;

    for (
      apr_xml_elem* node = parsedResult->first_child; node != NULL;
        node = node->next) {
        childElementCount++;

        if (childElementCount == 1) {
          checkMessageElement(node, "Hello, World");
        } else {
          checkNDCElement(node, "NDC goes here");
        }
    }

    CPPUNIT_ASSERT_EQUAL(2, childElementCount);
  }

  /**
   * Tests getLocationInfo and setLocationInfo.
   */
 void testGetSetLocationInfo() {
    XMLLayout layout;
    CPPUNIT_ASSERT_EQUAL(false, layout.getLocationInfo());
    layout.setLocationInfo(true);
    CPPUNIT_ASSERT_EQUAL(true, layout.getLocationInfo());
    layout.setLocationInfo(false);
    CPPUNIT_ASSERT_EQUAL(false, layout.getLocationInfo());
  }

  /**
   * Tests activateOptions().
   */
  void testActivateOptions() {
    Pool p;
    XMLLayout layout;
    layout.activateOptions(p);
  }

    /**
     * Tests problematic characters in multiple fields.
     * @throws Exception if parser can not be constructed or source is not a valid XML document.
     */
    void testProblemCharacters()  {
      std::string problemName = "com.example.bar<>&\"'";
      LogString problemNameLS = LOG4CXX_STR("com.example.bar<>&\"'");
      LoggerPtr logger = Logger::getLogger(problemName);
      LevelPtr level = new XLevel(6000, problemNameLS, 7);
      NDC::push(problemName);
      MDC::clear();
      MDC::put(problemName, problemName);
      LoggingEventPtr event =
        new LoggingEvent(logger, level, problemNameLS, LOG4CXX_LOCATION);
      XMLLayout layout;
      layout.setProperties(true);
      Pool p;
      LogString result;
      layout.format(result, event, p);
      MDC::clear();

      apr_xml_elem* parsedResult = parse(result, p);
      checkEventElement(parsedResult, event);

      int childElementCount = 0;

      for (
        apr_xml_elem* node = parsedResult->first_child; node != NULL;
          node = node->next) {
          childElementCount++;
          switch(childElementCount) {
              case 1:
              checkMessageElement(node, problemName);
              break;

              case 2:
              checkNDCElement(node, problemName);
              break;

              case 3:
              checkPropertiesElement(node, problemName.c_str(), problemName.c_str());
              break;

              default:
              break;
          }

      }
      CPPUNIT_ASSERT_EQUAL(3, childElementCount);
    }

    /**
      * Tests CDATA element within NDC content.  See bug 37560.
      */
    void testNDCWithCDATA() {
        LoggerPtr logger = Logger::getLogger("com.example.bar");
        LevelPtr level = Level::getInfo();
        std::string ndcMessage ="<envelope><faultstring><![CDATA[The EffectiveDate]]></faultstring><envelope>";
        NDC::push(ndcMessage);
        LoggingEventPtr event =
          new LoggingEvent(
            logger, level, LOG4CXX_STR("Hello, World"), LOG4CXX_LOCATION);
        XMLLayout layout;
        Pool p;
        LogString result;
        layout.format(result, event, p);
        NDC::clear();
        apr_xml_elem* parsedResult = parse(result, p);
        int ndcCount = 0;
        for(apr_xml_elem* node = parsedResult->first_child;
            node != NULL;
            node = node->next) {
            if (strcmp(node->name, "NDC") == 0) {
                ndcCount++;
                CPPUNIT_ASSERT_EQUAL(ndcMessage, getText(node));
            }
        }
        CPPUNIT_ASSERT_EQUAL(1, ndcCount);
   }

};


CPPUNIT_TEST_SUITE_REGISTRATION(XMLLayoutTest);

