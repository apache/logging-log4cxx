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

#include "../logunit.h"

#include <log4cxx/private/consolewriter_priv.h>
#include <log4cxx/helpers/pool.h>
#include <apr_file_io.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


LOGUNIT_CLASS(ConsoleWriterTest)
{
	LOGUNIT_TEST_SUITE(ConsoleWriterTest);
	LOGUNIT_TEST(testWriteEmbeddedNullCharacters);
	LOGUNIT_TEST_SUITE_END();

public:
	/**
	 * Tests writing to an unknown host.
	 */
	void testWriteEmbeddedNullCharacters()
	{
		Pool p;
		const char* tmpdir = NULL;
		apr_status_t stat = apr_temp_dir_get(&tmpdir, p.getAPRPool());
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);

		std::string path = tmpdir;
		path += "/log4cxx.test.log";

		remove(path.c_str());

		std::string message{"Hello\0World!", 12};

		{
			FILE *fp = fopen(path.c_str(), "wb");
			LOG4CXX_DECODE_CHAR(lsMessage, message);
			size_t written = helpers::writeToConsole(lsMessage, fp);
			LOGUNIT_ASSERT_EQUAL(message.size() + 1, written);
			fclose(fp);
		}

		std::string content;

		{
			FILE *fp = fopen(path.c_str(), "rb");
			content.resize(1024);
			size_t count = fread((void*)content.data(), 1, content.size(), fp);
			content.resize(count);
			fclose(fp);
		}

		LOGUNIT_ASSERT_EQUAL(content, message + "\n");
	}

};


LOGUNIT_TEST_SUITE_REGISTRATION(ConsoleWriterTest);
