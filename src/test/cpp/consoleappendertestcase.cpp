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

#include <log4cxx/consoleappender.h>
#include "logunit.h"
#include "writerappendertestcase.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

/**
   Unit tests of ConsoleAppender.
 */
class ConsoleAppenderTestCase : public WriterAppenderTestCase
{
		LOGUNIT_TEST_SUITE(ConsoleAppenderTestCase);
		//
		//    tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);
		LOGUNIT_TEST(testNoLayout);
		LOGUNIT_TEST_SUITE_END();


	public:

		WriterAppender* createWriterAppender() const
		{
			return new log4cxx::ConsoleAppender();
		}

		void testNoLayout()
		{
			Pool p;
			ConsoleAppenderPtr appender(new ConsoleAppender());
			appender->activateOptions(p);
			LoggerPtr logger(Logger::getRootLogger());
			logger->addAppender(appender);
			LOG4CXX_INFO(logger, "No layout specified for ConsoleAppender");
			logger->removeAppender(appender);
		}
};

LOGUNIT_TEST_SUITE_REGISTRATION(ConsoleAppenderTestCase);
