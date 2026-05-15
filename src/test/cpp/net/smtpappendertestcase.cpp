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

#define LOG4CXX_TEST 1
#include <log4cxx/private/log4cxx_private.h>

#include <log4cxx/net/smtpappender.h>
#include "../appenderskeletontestcase.h"
#include <log4cxx/xml/domconfigurator.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/simplelayout.h>
#include <log4cxx/helpers/onlyonceerrorhandler.h>

namespace LOG4CXX_NS
{
namespace net
{

class MockTriggeringEventEvaluator :
	public spi::TriggeringEventEvaluator
{
	public:
		DECLARE_LOG4CXX_OBJECT(MockTriggeringEventEvaluator)
		BEGIN_LOG4CXX_CAST_MAP()
		LOG4CXX_CAST_ENTRY(MockTriggeringEventEvaluator)
		LOG4CXX_CAST_ENTRY(spi::TriggeringEventEvaluator)
		END_LOG4CXX_CAST_MAP()

		MockTriggeringEventEvaluator()
		{
		}

		bool isTriggeringEvent(const spi::LoggingEventPtr& event) override
		{
			return true;
		}
	private:
		MockTriggeringEventEvaluator(const MockTriggeringEventEvaluator&);
		MockTriggeringEventEvaluator& operator=(const MockTriggeringEventEvaluator&);
};
}
}

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::net;

IMPLEMENT_LOG4CXX_OBJECT(MockTriggeringEventEvaluator)


/**
   Unit tests of log4cxx::SocketAppender
 */
class SMTPAppenderTestCase : public AppenderSkeletonTestCase
{
		LOGUNIT_TEST_SUITE(SMTPAppenderTestCase);
		//
		//    tests inherited from AppenderSkeletonTestCase
		//
		LOGUNIT_TEST(testDefaultThreshold);
		LOGUNIT_TEST(testSetOptionThreshold);
		LOGUNIT_TEST(testTrigger);
		LOGUNIT_TEST(testInvalid);
		LOGUNIT_TEST(testNegativeBufferSizeOption);
		LOGUNIT_TEST(testSubjectStripsCRLF);
		LOGUNIT_TEST(testAddressFieldsStripCRLF);
		LOGUNIT_TEST(testCleanFieldsArePreserved);
//#define LOG4CXX_TEST_EMAIL_AND_SMTP_HOST_ARE_IN_ENVIRONMENT_VARIABLES
#ifdef LOG4CXX_TEST_EMAIL_AND_SMTP_HOST_ARE_IN_ENVIRONMENT_VARIABLES
		// This test requires the following environment variables:
		// LOG4CXX_TEST_EMAIL_RECIPIENT - where the email is sent
		// LOG4CXX_TEST_SMTP_HOST_NAME - the email server
		LOGUNIT_TEST(testValid);
#endif
		LOGUNIT_TEST_SUITE_END();


	public:

		AppenderSkeleton* createAppenderSkeleton() const
		{
			return new log4cxx::net::SMTPAppender();
		}

		void setUp()
		{
		}

		void tearDown()
		{
			LogManager::resetConfiguration();
		}

		/**
		 * Tests that triggeringPolicy element will set evaluator.
		 */
		void testTrigger()
		{
			auto status = xml::DOMConfigurator::configure("input/xml/smtpAppender1.xml");
			LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
			auto appender = log4cxx::cast<SMTPAppender>(Logger::getRootLogger()->getAppender(LOG4CXX_STR("A1")));
			LOGUNIT_ASSERT(appender);
			auto evaluator = appender->getEvaluator();
			LOGUNIT_ASSERT(evaluator);
			LOGUNIT_ASSERT_EQUAL(true, evaluator->instanceof(MockTriggeringEventEvaluator::getStaticClass()));
		}

		void testInvalid()
		{
			auto appender = std::make_shared<SMTPAppender>();
			appender->setSMTPHost(LOG4CXX_STR("smtp.invalid"));
			appender->setTo(LOG4CXX_STR("you@example.invalid"));
			appender->setFrom(LOG4CXX_STR("me@example.invalid"));
			appender->setLayout(std::make_shared<SimpleLayout>());
			Pool p;
			appender->activateOptions(p);
			auto root = Logger::getRootLogger();
			root->addAppender(appender);
			LOG4CXX_INFO(root, "Hello, World.");
			LOG4CXX_ERROR(root, "Sending Message"); // The DefaultEvaluator should trigger e-mail generation
			auto eh = dynamic_cast<helpers::OnlyOnceErrorHandler*>(appender->getErrorHandler().get());
			LOGUNIT_ASSERT(eh);
			LOGUNIT_ASSERT(eh->errorReported());
		}

		void testNegativeBufferSizeOption()
		{
			SMTPAppender appender;
			appender.setOption(LOG4CXX_STR("BUFFERSIZE"), LOG4CXX_STR("-10"));
			LOGUNIT_ASSERT_EQUAL(1, appender.getBufferSize());
		}

		/**
		 * SMTPSession::toAscii is the library's sanitization step for values
		 * destined for SMTP headers via libesmtp; it rewrites non-ASCII to '?'
		 * but does not touch CR/LF. Before the fix, a Subject containing CRLF
		 * was passed verbatim to smtp_set_header — RFC 5322 §2.1 treats CRLF
		 * as the header-field terminator, so an attacker controlling a
		 * configured Subject (e.g. via property substitution) could inject a
		 * fresh Bcc/Cc header. Each public setter must strip CR (0x0D) and
		 * LF (0x0A) so the boundary is enforced regardless of how the value
		 * reaches the appender.
		 */
		void testSubjectStripsCRLF()
		{
			SMTPAppender appender;
			appender.setSubject(LOG4CXX_STR("Notification\r\nBcc: attacker@example.invalid"));
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("NotificationBcc: attacker@example.invalid")),
				appender.getSubject());

			appender.setSubject(LOG4CXX_STR("alert\nfollow-up"));
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("alertfollow-up")),
				appender.getSubject());

			appender.setSubject(LOG4CXX_STR("loose\rCR"));
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("looseCR")),
				appender.getSubject());
		}

		void testAddressFieldsStripCRLF()
		{
			SMTPAppender appender;
			appender.setFrom(LOG4CXX_STR("me@example.invalid\r\nBcc: x@y"));
			appender.setTo(LOG4CXX_STR("you@example.invalid\nBcc: x@y"));
			appender.setCc(LOG4CXX_STR("a@b\r,c@d"));
			appender.setBcc(LOG4CXX_STR("z@example.invalid\n"));

			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("me@example.invalidBcc: x@y")),
				appender.getFrom());
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("you@example.invalidBcc: x@y")),
				appender.getTo());
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("a@b,c@d")),
				appender.getCc());
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("z@example.invalid")),
				appender.getBcc());
		}

		void testCleanFieldsArePreserved()
		{
			// Whitespace, tabs, commas, and non-ASCII are deliberately untouched
			// here: only CR/LF are stripped. toAscii continues to handle non-ASCII
			// at SMTP-message construction time.
			SMTPAppender appender;
			appender.setSubject(LOG4CXX_STR("  Spaced subject\t"));
			appender.setTo(LOG4CXX_STR("a@example.invalid, b@example.invalid"));
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("  Spaced subject\t")),
				appender.getSubject());
			LOGUNIT_ASSERT_EQUAL(
				LogString(LOG4CXX_STR("a@example.invalid, b@example.invalid")),
				appender.getTo());
		}

		void testValid()
		{
			auto status = xml::DOMConfigurator::configure("input/xml/smtpAppenderValid.xml");
			LOGUNIT_ASSERT_EQUAL(status, spi::ConfigurationStatus::Configured);
			auto root = Logger::getRootLogger();
			LOG4CXX_INFO(root, "Hello, World.\n\nThis paragraph should be preceeded by a blank line.");

			auto appender = log4cxx::cast<SMTPAppender>(root->getAppender(LOG4CXX_STR("A1")));
			LOGUNIT_ASSERT(appender);
			auto eh = dynamic_cast<helpers::OnlyOnceErrorHandler*>(appender->getErrorHandler().get());
			LOGUNIT_ASSERT(eh);
			LOGUNIT_ASSERT(!eh->errorReported());
		}
};

LOGUNIT_TEST_SUITE_REGISTRATION(SMTPAppenderTestCase);

