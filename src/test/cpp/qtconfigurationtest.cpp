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
#include "logunit.h"
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/optionconverter.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx-qt/configuration.h>
#include <log4cxx-qt/transcoder.h>
#include <apr_file_io.h>
#include "apr_time.h"
#include <QCoreApplication>
#include <QFileInfo>

using namespace log4cxx;

LOGUNIT_CLASS(QtConfigurationTestCase)
{
	LOGUNIT_TEST_SUITE(QtConfigurationTestCase);
	LOGUNIT_TEST(test1);
	LOGUNIT_TEST_SUITE_END();
	helpers::Pool m_pool;
	char m_buf[2048];
	QString m_configFile;
	spi::ConfigurationStatus m_status;
public:

	void copyPropertyFile(const LogString& lsDestDir)
	{
		LOG4CXX_ENCODE_CHAR(destDir, lsDestDir);
		auto status = apr_file_copy
		   ( "input/qtConfigurationTest.properties"
		   , (destDir + "/qtConfigurationTest.properties").c_str()
		   , APR_FPROT_UREAD | APR_FPROT_UWRITE
		   , m_pool.getAPRPool()
		   );
		if (APR_SUCCESS != status)
		   helpers::LogLog::warn(helpers::Exception::makeMessage(lsDestDir + LOG4CXX_STR("/qtConfigurationTest.properties"), status));
	}

	void setUp()
	{
		int argc{ 0 };
		char* argv[] = {nullptr};
		static QCoreApplication init_once{argc, argv};
		auto lsTempDir = helpers::OptionConverter::getSystemProperty(LOG4CXX_STR("TEMP"), LOG4CXX_STR("/tmp"));
		copyPropertyFile(lsTempDir);
		LOG4CXX_ENCODE_QSTRING(qTempDir, lsTempDir);
		QVector<QString> paths
			{ qTempDir
			};
		QVector<QString> names
			{ LOG4CXX_STR("qtConfigurationTest.properties")
			};
		std::tie(m_status, m_configFile) = qt::Configuration::configureFromFileAndWatch(paths, names);
	}

	void tearDown()
	{
		LogManager::shutdown();
		apr_file_remove(m_configFile.toUtf8().constData(), m_pool.getAPRPool());
		// wait 0.2 sec to ensure the file is really gone on Windows
		apr_sleep(200000);
	}

	void test1()
	{
		LOGUNIT_ASSERT_EQUAL(m_status, spi::ConfigurationStatus::Configured);
		auto debugLogger1 = LogManager::getLogger(LOG4CXX_STR("test1"));
		LOGUNIT_ASSERT(debugLogger1);
		LOGUNIT_ASSERT(!debugLogger1->isDebugEnabled());
		auto debugLogger2 = LogManager::getLogger(LOG4CXX_STR("test2"));
		LOGUNIT_ASSERT(debugLogger2);
		LOGUNIT_ASSERT(debugLogger2->isDebugEnabled());
		LOGUNIT_ASSERT(QFileInfo(m_configFile).exists());
		// wait 2 sec to ensure the modification time is different to that held in the WatchDog
		apr_sleep(2000000);
		auto debugLogger = LogManager::getLogger(LOG4CXX_STR("test3"));
		LOGUNIT_ASSERT(debugLogger);
		LOGUNIT_ASSERT(!debugLogger->isDebugEnabled());

		// Append a configuration for test3 logger
		helpers::ByteBuffer bbuf(m_buf, sizeof(m_buf));
		int sz = 0;
		for (const char* p = "\nlog4j.logger.test3=DEBUG\n"; *p; ++p)
		{
			bbuf.put(*p);
			++sz;
		}
		bbuf.position(0);
		bbuf.limit(sz);
		LOG4CXX_DECODE_QSTRING(lsConfigFile, m_configFile);
		helpers::FileOutputStream of(lsConfigFile, true);
		of.write(bbuf, m_pool);
		of.flush(m_pool);
		of.close(m_pool);
		helpers::LogLog::debug(LOG4CXX_STR("Updated ") + lsConfigFile);

		// wait 1.5 sec for the change to be noticed
		for (auto i : {1, 2, 3, 4, 5})
		{
			QCoreApplication::processEvents();
			apr_sleep(30000); // 30 ms
		}
		LOGUNIT_ASSERT(debugLogger->isDebugEnabled());
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(QtConfigurationTestCase);
