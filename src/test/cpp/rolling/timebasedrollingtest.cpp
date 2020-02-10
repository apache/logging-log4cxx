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

#include <vector>

#include <log4cxx/rolling/rollingfileappender.h>
#include <log4cxx/logger.h>
#include <log4cxx/consoleappender.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/patternlayout.h>
#include <log4cxx/rolling/timebasedrollingpolicy.h>
#include <log4cxx/helpers/simpledateformat.h>
#include <iostream>
#include <log4cxx/helpers/stringhelper.h>
#include "../util/compare.h"
#include "../logunit.h"

#include <apr_strings.h>
#include <apr_time.h>
#ifndef INT64_C
	#define INT64_C(x) x ## LL
#endif

// We often need one and the same date pattern, but in different contexts, to either easily embed it
// into other string literals or as an object. While macros are hard to debug, embedding into string
// literals is easier this way, because the compiler can automatically collaps them, and if we have
// one macro already, a second for a similar purpose shouldn't hurt as well.
#define DATE_PATTERN        "yyyy-MM-dd_HH_mm_ss"
#define DATE_PATTERN_STR    LogString(LOG4CXX_STR("yyyy-MM-dd_HH_mm_ss"))
#define PATTERN_LAYOUT      LOG4CXX_STR("%c{1} - %m%n")

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::rolling;

/**
 * A rather exhaustive set of tests. Tests include leaving the ActiveFileName
 * argument blank, or setting it, with and without compression, and tests
 * with or without stopping/restarting the RollingFileAppender.
 *
 * The regression tests log a few times using a RollingFileAppender. Then,
 * they predict the names of the files which sould be generated and compare
 * them with witness files.
 *
 * <pre>
         Compression    ActiveFileName  Stop/Restart
 Test1      NO              BLANK          NO
 Test2      NO              BLANK          YES
 Test3      YES             BLANK          NO
 Test4      NO                SET          YES
 Test5      NO                SET          NO
 Test6      YES               SET          NO
 * </pre>
 */
LOGUNIT_CLASS(TimeBasedRollingTest)
{
	LOGUNIT_TEST_SUITE(TimeBasedRollingTest);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST(test2);
	LOGUNIT_TEST(test3);
	LOGUNIT_TEST(test4);
	LOGUNIT_TEST(test5);
	LOGUNIT_TEST(test6);
	LOGUNIT_TEST(test7);
	LOGUNIT_TEST_SUITE_END();

private:
	static LoggerPtr logger;

	/**
	 * Currently running test.
	 * <p>
	 * Number of currently running test, used e.g. for some generic code in {@link setUp()}.
	 * </p>
	 */
	size_t num_test;

	/**
	 * Build file names with timestamps.
	 * <p>
	 * This method builds some file names based on a hard coded date pattern, while the important
	 * thing is that the used time is "now" for the first and one additional second into the future
	 * for each subsequent file name. The method is used to build names which are expected to get
	 * created by loggers afterwards, so the existence of those files can be checked easily.
	 * </p>
	 * <p>
	 * The given {@code prefix} is for the file name only, we hard code "output" as directory.
	 * </p>
	 * <p>
	 * Using {@code startInFuture} the caller can specify if the first created file name uses "now"
	 * or already starts one second in the future. This depends on what the caller wants to check:
	 * If it is the existence of specially named files and the caller uses some generic log file to
	 * start with, it's most likely that the first file name to checks needs to be in the future,
	 * because new files are only created with subsequent log statements. The first goes to the
	 * generically named file, afterwards the test sleeps a bit and the next statement is creating
	 * the first file to check for. During the time between those two calls the current second and
	 * therefore "now" could have easily past and the first file name will never be found, because
	 * the rolling appender creates it with a newer "now", at least one second in the future.
	 * </p>
	 * @param[in,out]   pool
	 * @param[in]       prefix
	 * @param[in]       fileNames
	 * param[in,opt]    withCompression
	 * param[in,opt]    startInFuture
	 */
	template<size_t N>
	void buildTsFileNames(          Pool &       pool,
		const   logchar *    prefix,
		LogString   (&fileNames)[N],
		bool        withCompression = false,
		bool        startInFuture   = false)
	{
		SimpleDateFormat    sdf(DATE_PATTERN_STR);
		apr_time_t          now(apr_time_now());
		LogString           ext(withCompression ? LOG4CXX_STR(".gz") : LOG4CXX_STR(""));

		now += startInFuture ? APR_USEC_PER_SEC : 0;

		for (size_t i = 0; i < N; ++i)
		{
			fileNames[i].assign(LogString(LOG4CXX_STR("output/")) + prefix);
			sdf.format(fileNames[i], now, pool);
			fileNames[i].append(ext);

			now += APR_USEC_PER_SEC;
		}
	}

	/**
	 * Log some msg and sleep.
	 * <p>
	 * Most tests need to log some message to some files and sleep afterwards, to spread the msgs
	 * over time and timestamp based named files. This method handles this for all tests to not need
	 * to replicate the same code AND deals with the fact that the logigng statements should contain
	 * the original src function and line. For that to work each caller needs to provide us the
	 * additional information and we redefine LOG4CXX_LOCATION to use that provided data instead of
	 * that from the compiler when a log statement is issued. While this is a bit ugly, because we
	 * need to duplicate the definition of LOG4CXX_LOCATION, it is easier than to duplicate the code
	 * for logging and sleeping per test in this file.
	 * </p>
	 * <p>
	 * The given wait factor is always multiplied with 1 second and the result is waited for, so a
	 * caller needs to e.g. provide {@code 0.5} if it needs log statements to distribute over given
	 * files, resulting in two statements per file. If the caller needs indivdual file to check for
	 * their existence, {@code 1} can be provided, which ensures that we wait for at least the next
	 * second.
	 * </p>
	 * <p>
	 * It is important the the caller provides aus with {@code __LOG4CXX_FUNC__} instead of only
	 * {@code __FUNC__} or such, because the latter is compiler specific and log4cxx already deals
	 * with such things.
	 * </p>
	 * <p>
	 * We had macro wrappers around this method dealing with such things in the past, but as args
	 * where added, those become more and more difficult to maintain properly and therefore removed.
	 * </p>
	 * @param[in,out]   pool
	 * @param[in]       howOften
	 * @param[in]       srcFunc
	 * @param[in]       srcLine
	 * @param[in,opt]   startWith
	 * @param[in]       waitFactor
	 */
	void logMsgAndSleep(Pool &       pool,
		size_t      howOften,
		std::string srcFunc,
		size_t      srcLine,
		size_t      startWith   = 0,
		float       waitFactor  = 0.5)
	{
#undef  LOG4CXX_LOCATION
#define LOG4CXX_LOCATION ::log4cxx::spi::LocationInfo(  \
	__FILE__,                   \
	srcFunc.c_str(),            \
	srcLine)

		for (size_t i = startWith; i < startWith + howOften; ++i)
		{
			std::string message("Hello---");
			message.append(pool.itoa(i));

			LOG4CXX_DEBUG(logger, message);
			apr_sleep(APR_USEC_PER_SEC * waitFactor);
		}

#undef  LOG4CXX_LOCATION
#define LOG4CXX_LOCATION ::log4cxx::spi::LocationInfo(  \
	__FILE__,                   \
	__LOG4CXX_FUNC__,           \
	__LINE__)
	}

	/**
	 * Check witness by comparing file contents.
	 * <p>
	 * This method checks the witness for some test by comparing the contents of the given file used
	 * by that test. To find the corresponding witness, the prefix of the test needs to be provided,
	 * which is some unique part of the file name to use, while we hard code the parent dir and
	 * other non changing parts of the name.
	 * </p>
	 * <p>
	 * We don't use a wrapper macro this time because the src line should have the same name in all
	 * compilers and is easily to add for the caller.
	 * </p>
	 * @param[in,out]   pool
	 * @param[in]       prefix
	 * @param[in]       fileName
	 * @param[in]       witnessIdx
	 * @param[in]       srcLine
	 */
	void compareWitness(        Pool &       pool,
		const   logchar *    prefix,
		const   LogString &  fileName,
		size_t      witnessIdx,
		size_t      srcLine)
	{
		LogString   witness(LOG4CXX_STR("witness/rolling/tbr-"));
		witness.append(prefix);

		StringHelper::toString(witnessIdx, pool, witness);
		LOGUNIT_ASSERT_SRCL(Compare::compare(fileName, File(witness)), srcLine);
	}

	/**
	 * Check witnesses by comparing file contents.
	 * <p>
	 * This method is a wrapper around {@link compareWitness}, used to iterate over all files from a
	 * given test.
	 * </p>
	 * @param[in,out]   pool
	 * @param[in]       prefix
	 * @param[in]       fileNames
	 * @param[in]       srcLine
	 */
	template<size_t N>
	void compareWitnesses(          Pool &       pool,
		const   logchar *    prefix,
		LogString   (&fileNames)[N],
		size_t      srcLine)
	{
		for (int i = 0; i < N; ++i)
		{
			this->compareWitness(pool, prefix, fileNames[i], i, srcLine);
		}
	}

	/**
	 * Check existing files.
	 * <p>
	 * This method checks that the first N - 1 files of the given array actually exist and compares
	 * the last one by content to some witness.
	 * </p>
	 * <p>
	 * We don't use a wrapper macro this time because the src line schould have the same name in all
	 * compilers and is easily to add for the caller.
	 * </p>
	 * @param[in,out]   pool
	 * @param[in]       prefix
	 * @param[in]       fileNames
	 * @param[in]       srcLine
	 */
	template<size_t N>
	void checkFilesExist(           Pool &       pool,
		const   logchar *    prefix,
		LogString   (&fileNames)[N],
		size_t      srcLine)
	{
		for (int i = 0; i < N - 1; ++i)
		{
			LOGUNIT_ASSERT_EQUAL_SRCL(true, File(fileNames[0]).exists(pool), srcLine);
		}

		this->compareWitness(pool, prefix, fileNames[N - 1], N - 1, srcLine);
	}

	/**
	 * Let the current second pass.
	 * <p>
	 * This method assures that the current second and some additional time gets passed before
	 * returning.
	 * </p>
	 * @param[in,opt] millis
	 */
	void delayUntilNextSecond(size_t millis = 100)
	{
		apr_time_t now  = apr_time_now();
		apr_time_t next = ((now / APR_USEC_PER_SEC) + 1) * APR_USEC_PER_SEC + millis * 1000L;

		apr_sleep(next - now);
	}

	/**
	 * Let the current second pass with some msg.
	 * <p>
	 * This method works exactly like {@link delayUntilNextSecond(size_t)}, but additionally prints
	 * a message before and after the wait on STDOUT for debugging purposes.
	 * </p>
	 * @param[in,opt] millis
	 */
	void delayUntilNextSecondWithMsg(size_t millis = 100)
	{
		std::cout << "Waiting until next second and " << millis << " millis.";
		delayUntilNextSecond(millis);
		std::cout << "Done waiting." << std::endl;
	}

	/**
	 * Delete generic log files.
	 * <p>
	 * Some tests use generic log file names which may already be available during subsequent calls
	 * to the test and influence their behavior, e.g. because RollingFileAppender uses the last
	 * modification time of already existing files to create their internal names. Such a date may
	 * be from the arbitrary past, but ost of the test assumes operations like rollovers within few
	 * seconds around "new". Thos assumptions will fail for older existing files. So this method can
	 * be called during {@link setUp()} of an test to clear such generically named files for each
	 * test. We currently only care about {@code output/testxy.log}.
	 * </p>
	 * @param[in] num_test
	 */
	void deleteGenericLogFilePerTest(size_t num_test)
	{
		Pool        pool;
		LogString   path(LOG4CXX_STR("output/test"));

		StringHelper::toString(num_test, pool, path);
		path.append(LOG4CXX_STR(".log"));

		File(path).deleteFile(pool);
	}

	/**
	 * Setup for internal test call.
	 * <p>
	 * This method has a similar intention like {@link setUp()}, only that it focusses on internal
	 * calls of the tests, where we don't need to create some loggers and such, but may need to
	 * delete some files etc. to make tests work.
	 * </p>
	 * @param[in] num_test
	 */
	void internalSetUp(size_t num_test)
	{
		this->deleteGenericLogFilePerTest(num_test);
	}

	/**
	 * Counterpart for {@like internalSetUp(size_t)}.
	 * <p>
	 * Counterpart for {@like internalSetUp(size_t)}.
	 * </p>
	 */
	void internalTearDown()
	{
		// Nothing to do currently.
	}

public:
	/**
	 * Extract number of current test.
	 * <p>
	 * {@code setUp()} needs the number of the current runnign test for some generic work and this
	 * is the only place where we can extract and save it in the instance.
	 * </p>
	 */
	void setCase(abts_case * tc)
	{
		LogUnit::TestFixture::setCase(tc);
		this->num_test = tc->suite->num_test;
	}

	void setUp()
	{
		LoggerPtr root(Logger::getRootLogger());
		root->addAppender(
			new ConsoleAppender(
				new PatternLayout(
					LOG4CXX_STR("%d{ABSOLUTE} [%t] %level %c{2}#%M:%L - %m%n"))));
		this->internalSetUp(this->num_test);
	}

	void tearDown()
	{
		this->internalTearDown();
		LogManager::shutdown();
	}

	/**
	 * Test rolling without compression, activeFileName left blank, no stop/start
	 */
	void test1()
	{
		Pool        pool;
		const   size_t      nrOfFileNames = 4;
		LogString   fileNames[nrOfFileNames];

		PatternLayoutPtr        layout( new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa(    new RollingFileAppender());
		rfa->setLayout(layout);

		TimeBasedRollingPolicyPtr tbrp(new TimeBasedRollingPolicy());
		tbrp->setFileNamePattern(LOG4CXX_STR("output/test1-%d{" DATE_PATTERN "}"));
		tbrp->activateOptions(pool);
		rfa->setRollingPolicy(tbrp);
		rfa->activateOptions(pool);
		logger->addAppender(rfa);

		this->buildTsFileNames(pool, LOG4CXX_STR("test1-"), fileNames);
		this->delayUntilNextSecondWithMsg();
		this->logMsgAndSleep(   pool, nrOfFileNames + 1, __LOG4CXX_FUNC__, __LINE__);
		this->compareWitnesses( pool, LOG4CXX_STR("test1."), fileNames, __LINE__);
	}

	/**
	 * No compression, with stop/restart, activeFileName left blank
	 */
	void test2()
	{
		Pool        pool;
		const   size_t      nrOfFileNames = 4;
		LogString   fileNames[nrOfFileNames];

		PatternLayoutPtr        layout1(new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa1(   new RollingFileAppender());
		rfa1->setLayout(layout1);

		TimeBasedRollingPolicyPtr tbrp1(new TimeBasedRollingPolicy());
		tbrp1->setFileNamePattern(LOG4CXX_STR("output/test2-%d{" DATE_PATTERN "}"));
		tbrp1->activateOptions(pool);
		rfa1->setRollingPolicy(tbrp1);
		rfa1->activateOptions(pool);
		logger->addAppender(rfa1);

		this->buildTsFileNames(pool, LOG4CXX_STR("test2-"), fileNames);
		this->delayUntilNextSecondWithMsg();
		this->logMsgAndSleep(pool, 3, __LOG4CXX_FUNC__, __LINE__);

		logger->removeAppender(rfa1);
		rfa1->close();

		PatternLayoutPtr        layout2(new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa2(   new RollingFileAppender());
		rfa2->setLayout(layout2);

		TimeBasedRollingPolicyPtr tbrp2 = new TimeBasedRollingPolicy();
		tbrp2->setFileNamePattern(LOG4CXX_STR("output/test2-%d{" DATE_PATTERN "}"));
		tbrp2->activateOptions(pool);
		rfa2->setRollingPolicy(tbrp2);
		rfa2->activateOptions(pool);
		logger->addAppender(rfa2);

		this->logMsgAndSleep(   pool, 2, __LOG4CXX_FUNC__, __LINE__, 3);
		this->compareWitnesses( pool, LOG4CXX_STR("test2."), fileNames, __LINE__);
	}

	/**
	 * With compression, activeFileName left blank, no stop/restart
	 */
	void test3()
	{
		Pool        pool;
		const   size_t      nrOfFileNames = 4;
		LogString   fileNames[nrOfFileNames];

		PatternLayoutPtr        layout( new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa(    new RollingFileAppender());
		rfa->setAppend(false);
		rfa->setLayout(layout);

		TimeBasedRollingPolicyPtr tbrp = new TimeBasedRollingPolicy();
		tbrp->setFileNamePattern(LogString(LOG4CXX_STR("output/test3-%d{" DATE_PATTERN "}.gz")));
		tbrp->activateOptions(pool);
		rfa->setRollingPolicy(tbrp);
		rfa->activateOptions(pool);
		logger->addAppender(rfa);

		this->buildTsFileNames(pool, LOG4CXX_STR("test3-"), fileNames, true);
		fileNames[3].resize(fileNames[3].size() - 3);
		this->delayUntilNextSecondWithMsg();
		this->logMsgAndSleep(   pool, nrOfFileNames + 1, __LOG4CXX_FUNC__, __LINE__);
		this->checkFilesExist(  pool, LOG4CXX_STR("test3."), fileNames, __LINE__);
	}

	/**
	 * Without compression, activeFileName set,  with stop/restart
	 */
	void test4()
	{
		Pool        pool;
		const   size_t      nrOfFileNames = 4;
		LogString   fileNames[nrOfFileNames];

		PatternLayoutPtr        layout1(new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa1(   new RollingFileAppender());
		rfa1->setLayout(layout1);

		TimeBasedRollingPolicyPtr tbrp1 = new TimeBasedRollingPolicy();
		rfa1->setFile(LOG4CXX_STR("output/test4.log"));
		tbrp1->setFileNamePattern(LOG4CXX_STR("output/test4-%d{" DATE_PATTERN "}"));
		tbrp1->activateOptions(pool);
		rfa1->setRollingPolicy(tbrp1);
		rfa1->activateOptions(pool);
		logger->addAppender(rfa1);

		this->buildTsFileNames(pool, LOG4CXX_STR("test4-"), fileNames);
		fileNames[3].assign(rfa1->getFile());
		this->delayUntilNextSecondWithMsg();
		this->logMsgAndSleep(pool, 3, __LOG4CXX_FUNC__, __LINE__);

		logger->removeAppender(rfa1);
		rfa1->close();

		PatternLayoutPtr        layout2(new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa2(   new RollingFileAppender());
		rfa2->setLayout(layout2);

		TimeBasedRollingPolicyPtr tbrp2 = new TimeBasedRollingPolicy();
		tbrp2->setFileNamePattern(LOG4CXX_STR("output/test4-%d{" DATE_PATTERN "}"));
		rfa2->setFile(fileNames[3]);
		tbrp2->activateOptions(pool);
		rfa2->setRollingPolicy(tbrp2);
		rfa2->activateOptions(pool);
		logger->addAppender(rfa2);

		this->logMsgAndSleep(   pool, 2, __LOG4CXX_FUNC__, __LINE__, 3);
		this->compareWitnesses( pool, LOG4CXX_STR("test4."), fileNames, __LINE__);
	}

	/**
	 * No compression, activeFileName set,  without stop/restart
	 */
	void test5()
	{
		Pool        pool;
		const   size_t      nrOfFileNames = 4;
		LogString   fileNames[nrOfFileNames];

		PatternLayoutPtr        layout( new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa(    new RollingFileAppender());
		rfa->setLayout(layout);

		TimeBasedRollingPolicyPtr tbrp = new TimeBasedRollingPolicy();
		tbrp->setFileNamePattern(LOG4CXX_STR("output/test5-%d{" DATE_PATTERN "}"));
		rfa->setFile(LOG4CXX_STR("output/test5.log"));

		tbrp->activateOptions(pool);
		rfa->setRollingPolicy(tbrp);
		rfa->activateOptions(pool);
		logger->addAppender(rfa);

		this->buildTsFileNames(pool, LOG4CXX_STR("test5-"), fileNames);
		fileNames[3].assign(rfa->getFile());
		this->delayUntilNextSecondWithMsg();
		this->logMsgAndSleep(   pool, nrOfFileNames + 1, __LOG4CXX_FUNC__, __LINE__);
		this->compareWitnesses( pool, LOG4CXX_STR("test5."), fileNames, __LINE__);
	}

	/**
	 * With compression, activeFileName set, no stop/restart,
	 */
	void test6()
	{
		Pool        pool;
		const   size_t      nrOfFileNames = 4;
		LogString   fileNames[nrOfFileNames];

		PatternLayoutPtr        layout( new PatternLayout(PATTERN_LAYOUT));
		RollingFileAppenderPtr  rfa(    new RollingFileAppender());
		rfa->setAppend(false);
		rfa->setLayout(layout);

		TimeBasedRollingPolicyPtr tbrp = new TimeBasedRollingPolicy();
		tbrp->setFileNamePattern(LogString(LOG4CXX_STR("output/test6-%d{" DATE_PATTERN "}.gz")));
		rfa->setFile(LOG4CXX_STR("output/test6.log"));
		tbrp->activateOptions(pool);
		rfa->setRollingPolicy(tbrp);
		rfa->activateOptions(pool);
		logger->addAppender(rfa);

		this->buildTsFileNames(pool, LOG4CXX_STR("test6-"), fileNames, true);
		fileNames[3].assign(rfa->getFile());
		this->delayUntilNextSecondWithMsg();
		this->logMsgAndSleep(   pool, nrOfFileNames + 1, __LOG4CXX_FUNC__, __LINE__);
		this->checkFilesExist(  pool, LOG4CXX_STR("test6."), fileNames, __LINE__);
	}

	/**
	 * Repeat some test with generic file name.s
	 * <p>
	 * This test calls some tests which use generic file names and will only work properly if those
	 * got deleted before running the test during setup.
	 * </p>
	 */
	void test7()
	{
		typedef void (TimeBasedRollingTest::*Test)();
		typedef std::vector<Test> Tests;

		Tests   tests(10);
		size_t  numTest = 0;

		tests.at(4) = &TimeBasedRollingTest::test4;
		tests.at(5) = &TimeBasedRollingTest::test5;
		tests.at(6) = &TimeBasedRollingTest::test6;

		for (size_t numTest = 1; numTest < tests.size(); ++numTest)
		{
			Test test(tests.at(numTest));

			if (!test)
			{
				continue;
			}

			this->internalSetUp(numTest);
			(this->*test)();
			this->internalTearDown();
		}
	}
};

LoggerPtr TimeBasedRollingTest::logger(Logger::getLogger("org.apache.log4j.TimeBasedRollingTest"));

LOGUNIT_TEST_SUITE_REGISTRATION(TimeBasedRollingTest);
