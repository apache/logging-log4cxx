/*
 * Copyright 2004 The Apache Software Foundation.
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

#include "fileappendertestcase.h"
#include <cppunit/extensions/HelperMacros.h>
#include <log4cxx/helpers/objectptr.h>
#include <log4cxx/fileappender.h>
#include "insertwide.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

WriterAppender* FileAppenderAbstractTestCase::createWriterAppender() const {
    return createFileAppender();
}


/**
   Unit tests of log4cxx::FileAppender
 */
class FileAppenderTestCase : public FileAppenderAbstractTestCase
{
	CPPUNIT_TEST_SUITE(FileAppenderTestCase);
                //
                //    tests inherited from AppenderSkeletonTestCase
                //
                CPPUNIT_TEST(testDefaultThreshold);
                CPPUNIT_TEST(testSetOptionThreshold);

                //  tests defined here
                CPPUNIT_TEST(testSetDoubleBackslashes);
                CPPUNIT_TEST(testStripDuplicateBackslashes);

	CPPUNIT_TEST_SUITE_END();




public:

        FileAppender* createFileAppender() const {
          return new log4cxx::FileAppender();
        }

        void testSetDoubleBackslashes() {
            FileAppender appender;
            appender.setOption(LOG4CXX_STR("FILE"), LOG4CXX_STR("output\\\\temp"));
            const File& file = appender.getFile();
            CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("output\\temp"), file.getName()); 
        }

          /**
           * Tests that double backslashes in filespecs are stripped
           *  on calls to setOption.
           * @since 0.9.8
           */
        void testStripDoubleBackslashes() {

            FileAppender appender;
            appender.setOption(LOG4CXX_STR("FILE"), LOG4CXX_STR("output\\\\temp"));
            const File& file = appender.getFile();
            CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("output\\temp"), file.getName()); 
        }

          /**
           * Tests stripDuplicateBackslashes
           *
           * @since 0.9.8
           */
        void testStripDuplicateBackslashes() {
             CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("\\foo\\bar\\foo"), 
                 FileAppender::stripDuplicateBackslashes(LOG4CXX_STR("\\foo\\bar\\foo")));
             CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("\\foo\\bar\\foo\\"), 
                FileAppender::stripDuplicateBackslashes(LOG4CXX_STR("\\\\foo\\\\bar\\\\foo\\\\")));
             CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("\\foo\\bar\\foo\\"), 
                FileAppender::stripDuplicateBackslashes(LOG4CXX_STR("\\foo\\bar\\foo\\")));
             //
             //   UNC's should either start with two backslashes and contain additional singles
             //       or four back slashes and addition doubles
             CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("\\\\foo\\bar\\foo"), 
                FileAppender::stripDuplicateBackslashes(LOG4CXX_STR("\\\\\\\\foo\\\\bar\\\\foo")));
             CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("\\\\foo\\bar\\foo"), 
                FileAppender::stripDuplicateBackslashes(LOG4CXX_STR("\\\\foo\\bar\\foo")));
	         //
	         //   it it starts with doubles but has no other path component
	         //      then it is a file path
             CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("\\foo.log"), 
                FileAppender::stripDuplicateBackslashes(LOG4CXX_STR("\\\\foo.log")));
	         //
	         //   it it starts with quads but has no other path component
	         //      then it is a UNC
             CPPUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR("\\\\foo.log"), 
                FileAppender::stripDuplicateBackslashes(LOG4CXX_STR("\\\\\\\\foo.log")));
          }  

};

CPPUNIT_TEST_SUITE_REGISTRATION(FileAppenderTestCase);
