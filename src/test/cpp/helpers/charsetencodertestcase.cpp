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

#include <log4cxx/helpers/charsetencoder.h>
#include "../logunit.h"
#include "../insertwide.h"
#include <log4cxx/helpers/bytebuffer.h>
#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/loglog.h>
#include <apr.h>
#include <apr_errno.h>
#include <condition_variable>
#include <thread>

using namespace log4cxx;
using namespace log4cxx::helpers;


LOGUNIT_CLASS(CharsetEncoderTestCase)
{
	LOGUNIT_TEST_SUITE(CharsetEncoderTestCase);
	LOGUNIT_TEST(encode1);
	LOGUNIT_TEST(encode2);
	LOGUNIT_TEST(encode3);
	LOGUNIT_TEST(encode4);
	LOGUNIT_TEST(encode5);
	LOGUNIT_TEST(thread1);
	LOGUNIT_TEST_SUITE_END();

	enum { BUFSIZE = 256 };

public:


	void encode1()
	{
		const LogString greeting(LOG4CXX_STR("Hello, World"));
		CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("US-ASCII")));
		char buf[BUFSIZE];
		ByteBuffer out(buf, BUFSIZE);
		LogString::const_iterator iter = greeting.begin();
		log4cxx_status_t stat = enc->encode(greeting, iter, out);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		LOGUNIT_ASSERT(iter == greeting.end());

		stat = enc->encode(greeting, iter, out);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		LOGUNIT_ASSERT_EQUAL((size_t) 12, out.position());

		out.flip();
		std::string encoded((const char*) out.data(), out.limit());
		LOGUNIT_ASSERT_EQUAL((std::string) "Hello, World", encoded);
		LOGUNIT_ASSERT(iter == greeting.end());
	}

	void encode2()
	{
		LogString greeting(BUFSIZE - 3, LOG4CXX_STR('A'));
		greeting.append(LOG4CXX_STR("Hello"));

		CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("US-ASCII")));

		char buf[BUFSIZE];
		ByteBuffer out(buf, BUFSIZE);
		LogString::const_iterator iter = greeting.begin();
		log4cxx_status_t stat = enc->encode(greeting, iter, out);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		LOGUNIT_ASSERT_EQUAL((size_t) 0, out.remaining());
		LOGUNIT_ASSERT_EQUAL(LOG4CXX_STR('o'), *(iter + 1));

		out.flip();
		std::string encoded((char*) out.data(), out.limit());
		out.clear();

		stat = enc->encode(greeting, iter, out);
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		LOGUNIT_ASSERT_EQUAL((size_t) 2, out.position());
		LOGUNIT_ASSERT(iter == greeting.end());

		stat = enc->encode(greeting, iter, out);
		out.flip();
		LOGUNIT_ASSERT_EQUAL(APR_SUCCESS, stat);
		encoded.append(out.data(), out.limit());

		std::string manyAs(BUFSIZE - 3, 'A');
		LOGUNIT_ASSERT_EQUAL(manyAs, encoded.substr(0, BUFSIZE - 3));
		LOGUNIT_ASSERT_EQUAL(std::string("Hello"), encoded.substr(BUFSIZE - 3));
	}


	void encode3()
	{
#if LOG4CXX_LOGCHAR_IS_WCHAR || LOG4CXX_LOGCHAR_IS_UNICHAR
		//   arbitrary, hopefully meaningless, characters from
		//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
		const logchar greet[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
		const char greet[] = { 'A',
				(char) 0xD8, (char) 0x85,
				(char) 0xD4, (char) 0xB0,
				(char) 0xE0, (char) 0xA6, (char) 0x86,
				(char) 0xE4, (char) 0xB8, (char) 0x83,
				(char) 0xD0, (char) 0x80,
				0
			};
#endif
		LogString greeting(greet);

		CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("US-ASCII")));

		char buf[BUFSIZE];
		ByteBuffer out(buf, BUFSIZE);

		LogString::const_iterator iter = greeting.begin();
		log4cxx_status_t stat = enc->encode(greeting, iter, out);
		out.flip();
		LOGUNIT_ASSERT_EQUAL(true, CharsetEncoder::isError(stat));
		LOGUNIT_ASSERT_EQUAL((size_t) 1, out.limit());
		LOGUNIT_ASSERT_EQUAL(greet[1], *iter);
		LOGUNIT_ASSERT_EQUAL('A', out.data()[0]);
	}


	void encode4()
	{
		const char utf8_greet[] = { 'A',
				(char) 0xD8, (char) 0x85,
				(char) 0xD4, (char) 0xB0,
				(char) 0xE0, (char) 0xA6, (char) 0x86,
				(char) 0xE4, (char) 0xB8, (char) 0x83,
				(char) 0xD0, (char) 0x80,
				0
			};
#if LOG4CXX_LOGCHAR_IS_WCHAR || LOG4CXX_LOGCHAR_IS_UNICHAR
		//   arbitrary, hopefully meaningless, characters from
		//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
		const logchar greet[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
		const logchar* greet = utf8_greet;
#endif
		LogString greeting(greet);

		CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("UTF-8")));

		char buf[BUFSIZE];
		ByteBuffer out(buf, BUFSIZE);
		LogString::const_iterator iter = greeting.begin();
		log4cxx_status_t stat = enc->encode(greeting, iter, out);
		LOGUNIT_ASSERT_EQUAL(false, CharsetEncoder::isError(stat));
		stat = enc->encode(greeting, iter, out);
		LOGUNIT_ASSERT_EQUAL(false, CharsetEncoder::isError(stat));

		out.flip();
		LOGUNIT_ASSERT_EQUAL((size_t) 13, out.limit());

		for (size_t i = 0; i < out.limit(); i++)
		{
			LOGUNIT_ASSERT_EQUAL((int) utf8_greet[i], (int) out.data()[i]);
		}

		LOGUNIT_ASSERT(iter == greeting.end());
	}

	void encode5()
	{
		const char utf8_greet[] = { 'A',
				(char) 0xD8, (char) 0x85,
				(char) 0xD4, (char) 0xB0,
				(char) 0xE0, (char) 0xA6, (char) 0x86,
				(char) 0xE4, (char) 0xB8, (char) 0x83,
				(char) 0xD0, (char) 0x80,
				0
			};
#if LOG4CXX_LOGCHAR_IS_WCHAR || LOG4CXX_LOGCHAR_IS_UNICHAR
		//   arbitrary, hopefully meaningless, characters from
		//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
		const logchar greet[] = { L'A', 0x0605, 0x0530, 0x986, 0x4E03, 0x400, 0 };
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
		const logchar* greet = utf8_greet;
#endif
		LogString greeting(greet);

		try
		{
			std::locale::global(std::locale("en_US.UTF-8"));
			auto enc = CharsetEncoder::getEncoder(LOG4CXX_STR("locale"));

			char buf[BUFSIZE];
			ByteBuffer out(buf, BUFSIZE);
			LogString::const_iterator iter = greeting.begin();
			log4cxx_status_t stat = enc->encode(greeting, iter, out);
			LOGUNIT_ASSERT_EQUAL(false, CharsetEncoder::isError(stat));
			stat = enc->encode(greeting, iter, out);
			LOGUNIT_ASSERT_EQUAL(false, CharsetEncoder::isError(stat));

			out.flip();
			LOGUNIT_ASSERT_EQUAL((size_t) 13, out.limit());

			for (size_t i = 0; i < out.limit(); i++)
			{
				unsigned expected = (unsigned)utf8_greet[i];
				unsigned actual = (unsigned)out.data()[i];
				LOGUNIT_ASSERT_EQUAL(expected, actual);
			}

			LOGUNIT_ASSERT(iter == greeting.end());
		}
		catch (std::runtime_error& ex)
		{
			LogString msg;
			Transcoder::decode(ex.what(), msg);
			msg.append(LOG4CXX_STR(": "));
			msg.append(LOG4CXX_STR("en_US.UTF-8"));
			LogLog::warn(msg);
		}
	}

	class ThreadPackage
	{
		public:
			ThreadPackage(CharsetEncoderPtr& enc, int repetitions)
				: passCount(0), failCount(0), enc(enc), repetitions(repetitions)
			{
			}

			void await()
			{
				std::unique_lock<std::mutex> sync(lock);
				condition.wait(sync);
			}

			void signalAll()
			{
				std::unique_lock<std::mutex> sync(lock);
				condition.notify_all();
			}

			void fail()
			{
				std::lock_guard<std::mutex> sync(lock);
				++failCount;
			}

			void pass()
			{
				std::lock_guard<std::mutex> sync(lock);
				++passCount;
			}

			uint32_t getFail()
			{
				std::lock_guard<std::mutex> sync(lock);
				return failCount;
			}

			uint32_t getPass()
			{
				std::lock_guard<std::mutex> sync(lock);
				return passCount;
			}

			int getRepetitions()
			{
				return repetitions;
			}

			CharsetEncoderPtr& getEncoder()
			{
				return enc;
			}

			void run()
			{
#if LOG4CXX_LOGCHAR_IS_UTF8
				const logchar greet[] = { 'H', 'e', 'l', 'l', 'o', ' ',
						(char) 0xC2, (char) 0xA2,  //  cent sign
						(char) 0xC2, (char) 0xA9,  //  copyright
						(char) 0xc3, (char) 0xb4,  //  latin small letter o with circumflex
						0
					};
#endif
#if LOG4CXX_LOGCHAR_IS_WCHAR || LOG4CXX_LOGCHAR_IS_UNICHAR
				//   arbitrary, hopefully meaningless, characters from
				//     Latin, Arabic, Armenian, Bengali, CJK and Cyrillic
				const logchar greet[] = { L'H', L'e', L'l', L'l', L'o', L' ',
						0x00A2, 0x00A9, 0x00F4, 0
					};
#endif

				const char expected[] =  { 'H', 'e', 'l', 'l', 'o', ' ',
						(char) 0x00A2, (char) 0x00A9, (char) 0x00F4
					};

				LogString greeting(greet);

				await();

				for (int i = 0; i < getRepetitions(); i++)
				{
					bool pass = true;
					char buf[BUFSIZE];
					ByteBuffer out(buf, BUFSIZE);
					LogString::const_iterator iter = greeting.begin();
					log4cxx_status_t stat = getEncoder()->encode(greeting, iter, out);
					pass = (false == CharsetEncoder::isError(stat));

					if (pass)
					{
						stat = getEncoder()->encode(greeting, iter, out);
						pass = (false == CharsetEncoder::isError(stat));

						if (pass)
						{
							out.flip();
							pass = (sizeof(expected) == out.limit());

							for (size_t i = 0; i < out.limit() && pass; i++)
							{
								pass = (expected[i] == out.data()[i]);
							}

							pass = pass && (iter == greeting.end());
						}
					}

					if (pass)
					{
						ThreadPackage::pass();
					}
					else
					{
						fail();
					}
				}
			}

		private:
			ThreadPackage(const ThreadPackage&);
			ThreadPackage& operator=(ThreadPackage&);
			std::mutex lock;
			std::condition_variable condition;
			uint32_t passCount;
			uint32_t failCount;
			CharsetEncoderPtr enc;
			int repetitions;
	};

	void thread1()
	{
		enum { THREAD_COUNT = 10, THREAD_REPS = 10000 };
		std::thread threads[THREAD_COUNT];
		CharsetEncoderPtr enc(CharsetEncoder::getEncoder(LOG4CXX_STR("ISO-8859-1")));
		auto package = std::make_unique<ThreadPackage>(enc, THREAD_REPS);
		for (int i = 0; i < THREAD_COUNT; i++)
		{
			threads[i] = std::thread(&ThreadPackage::run, package.get());
		}
		//
		//   give time for all threads to be launched so
		//      we don't signal before everybody is waiting.
		std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
		package->signalAll();

		for (int i = 0; i < THREAD_COUNT; i++)
		{
			threads[i].join();
		}

		LOGUNIT_ASSERT_EQUAL((apr_uint32_t) 0, package->getFail());
		LOGUNIT_ASSERT_EQUAL((apr_uint32_t) THREAD_COUNT * THREAD_REPS, package->getPass());
	}

};

LOGUNIT_TEST_SUITE_REGISTRATION(CharsetEncoderTestCase);
