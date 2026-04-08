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

#include <log4cxx/file.h>
#include "logunit.h"
#include "insertwide.h"
#include <log4cxx/helpers/pool.h>
#include <apr_errno.h>
#include <log4cxx/helpers/exception.h>
#include <log4cxx/helpers/fileinputstream.h>

#include <log4cxx/helpers/outputstreamwriter.h>
#include <log4cxx/helpers/fileoutputstream.h>
#include <log4cxx/helpers/inputstreamreader.h>
#include <log4cxx/helpers/fileinputstream.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/transcoder.h>

#if LOG4CXX_CFSTRING_API
	#include <CoreFoundation/CFString.h>
#endif

using namespace log4cxx;
using namespace log4cxx::helpers;


LOGUNIT_CLASS(FileTestCase)
{
	LOGUNIT_TEST_SUITE(FileTestCase);
	LOGUNIT_TEST(defaultConstructor);
	LOGUNIT_TEST(defaultExists);
	LOGUNIT_TEST(defaultRead);
	LOGUNIT_TEST(propertyRead);
	LOGUNIT_TEST(propertyExists);
	LOGUNIT_TEST(fileWrite1);
#if LOG4CXX_WCHAR_T_API
	LOGUNIT_TEST(wcharConstructor);
#endif
#if LOG4CXX_UNICHAR_API
	LOGUNIT_TEST(unicharConstructor);
#endif
#if LOG4CXX_CFSTRING_API
	LOGUNIT_TEST(cfstringConstructor);
#endif
	LOGUNIT_TEST(copyConstructor);
	LOGUNIT_TEST(assignment);
	LOGUNIT_TEST(deleteBackslashedFileName);
	LOGUNIT_TEST(testSplitMultibyteUtf8);
	LOGUNIT_TEST(testInvalidUtf8);
	LOGUNIT_TEST_SUITE_END();

#ifdef _DEBUG
	struct Fixture
	{
		Fixture() {
			helpers::LogLog::setInternalDebugging(true);
		}
	} suiteFixture;
#endif

public:
	void defaultConstructor()
	{
		File defFile;
		LOGUNIT_ASSERT_EQUAL((LogString) LOG4CXX_STR(""), defFile.getPath());
	}



	void defaultExists()
	{
		File defFile;
		Pool pool;
		bool exists = defFile.exists(pool);
		LOGUNIT_ASSERT_EQUAL(false, exists);
	}

	// check default constructor. read() throws an exception
	// if no file name was given.
	void defaultRead()
	{
		File defFile;
		Pool pool;

		try
		{
			InputStreamPtr defInput = FileInputStreamPtr(new FileInputStream(defFile));
			InputStreamReaderPtr inputReader = InputStreamReaderPtr(new InputStreamReader(defInput));
			LogString contents(inputReader->read(pool));
			LOGUNIT_ASSERT(false);
		}
		catch (IOException& ex)
		{
			LOG4CXX_DECODE_CHAR(msg, ex.what());
			LogLog::debug(msg);
		}
	}


#if LOG4CXX_WCHAR_T_API
	void wcharConstructor()
	{
		File propFile(L"input/patternLayout1.properties");
		Pool pool;
		bool exists = propFile.exists(pool);
		LOGUNIT_ASSERT_EQUAL(true, exists);
	}
#endif

#if LOG4CXX_UNICHAR_API
	void unicharConstructor()
	{
		const log4cxx::UniChar filename[] = { 'i', 'n', 'p', 'u', 't', '/',
				'p', 'a', 't', 't', 'e', 'r', 'n', 'L', 'a', 'y', 'o', 'u', 't', '1', '.',
				'p', 'r', 'o', 'p', 'e', 'r', 't', 'i', 'e', 's', 0
			};
		File propFile(filename);
		Pool pool;
		bool exists = propFile.exists(pool);
		LOGUNIT_ASSERT_EQUAL(true, exists);
	}
#endif

#if LOG4CXX_CFSTRING_API
	void cfstringConstructor()
	{
		File propFile(CFSTR("input/patternLayout1.properties"));
		Pool pool;
		bool exists = propFile.exists(pool);
		LOGUNIT_ASSERT_EQUAL(true, exists);
	}
#endif

	void copyConstructor()
	{
		File propFile("input/patternLayout1.properties");
		File copy(propFile);
		Pool pool;
		bool exists = copy.exists(pool);
		LOGUNIT_ASSERT_EQUAL(true, exists);
	}

	void assignment()
	{
		File propFile("input/patternLayout1.properties");
		File copy = propFile;
		Pool pool;
		bool exists = copy.exists(pool);
		LOGUNIT_ASSERT_EQUAL(true, exists);
	}

	void propertyRead()
	{
		File propFile("input/patternLayout1.properties");
		Pool pool;
		InputStreamPtr propStream = FileInputStreamPtr(new FileInputStream(propFile));
		InputStreamReaderPtr propReader = InputStreamReaderPtr(new InputStreamReader(propStream));
		LogString props(propReader->read(pool));
		LogString line1(LOG4CXX_STR("# Licensed to the Apache Software Foundation (ASF) under one or more"));
		LOGUNIT_ASSERT_EQUAL(line1, props.substr(0, line1.length()));
	}

	void propertyExists()
	{
		File propFile("input/patternLayout1.properties");
		Pool pool;
		bool exists = propFile.exists(pool);
		LOGUNIT_ASSERT_EQUAL(true, exists);
	}

	void fileWrite1()
	{
		OutputStreamPtr fos = FileOutputStreamPtr(
				new FileOutputStream(LOG4CXX_STR("output/fileWrite1.txt")));
		OutputStreamWriterPtr osw = OutputStreamWriterPtr(new OutputStreamWriter(fos));

		Pool pool;
		LogString greeting(LOG4CXX_STR("Hello, World"));
		greeting.append(LOG4CXX_EOL);
		osw->write(greeting, pool);

		InputStreamPtr is = FileInputStreamPtr(
				new FileInputStream(LOG4CXX_STR("output/fileWrite1.txt")));
		InputStreamReaderPtr isr = InputStreamReaderPtr(new InputStreamReader(is));
		LogString reply = isr->read(pool);

		LOGUNIT_ASSERT_EQUAL(greeting, reply);
	}

	/**
	 *  Tests conversion of backslash containing file names.
	 *  Would cause infinite loop due to bug LOGCXX-105.
	 */
	void deleteBackslashedFileName()
	{
		File file("output\\bogus.txt");
		Pool pool;
		/*bool deleted = */file.deleteFile(pool);
	}

	class MockInputStream : public InputStream
	{
		ByteBuffer m_data;
	public:
		MockInputStream(const char* data, size_t charCount)
			: m_data(const_cast<char*>(data), charCount)
		{}

		int read(ByteBuffer& dst) override
		{
			auto availableBytes = m_data.remaining();
			if (availableBytes < 1)
				return -1;
			int count = 0;
			for (auto p = m_data.current(); count < availableBytes && dst.put(*p); ++p)
				++count;
			m_data.increment_position(count);
			return count;
		}

		void close() override {}
	};

	/**
	 * Tests behavior when a multibyte UTF-8 sequence occurs on a read boundary
	 */
	void testSplitMultibyteUtf8()
	{
		Pool p;
		// InputStreamReader uses a buffer of size 4096
		std::string input( 4094, 'A' );
		// räksmörgås.josefsson.org
		input.append("\162\303\244\153\163\155\303\266\162\147\303\245\163\056\152\157\163\145\146\163\163\157\156\056\157\162\147");
		InputStreamReader reader(std::make_shared<MockInputStream>(input.c_str(), input.size()), CharsetDecoder::getUTF8Decoder());
		auto contentLS = reader.read(p);
		LOG4CXX_ENCODE_CHAR(content, contentLS);
		LOGUNIT_ASSERT_EQUAL(input, content);
	}

	/**
	 * Tests behavior given an incomplete multibyte UTF-8 sequence in the input
	 */
	void testInvalidUtf8()
	{
		Pool p;
		// 0xC2 is a generic start byte for a 2-byte sequence in UTF-8.
		char input[] = { 'A', (char)0xC2, 'B', 'C', 0 };
		InputStreamReader reader(std::make_shared<MockInputStream>(input, 4), CharsetDecoder::getUTF8Decoder());
		try
		{
			reader.read(p);
			LOGUNIT_ASSERT(false);
		}
		catch (const Exception& ex)
		{
			LOG4CXX_DECODE_CHAR(msg, ex.what());
			LogLog::debug(msg);
		}
	}
};

LOGUNIT_TEST_SUITE_REGISTRATION(FileTestCase);
