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

#include <stdlib.h>
#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/basicconfigurator.h>
#include <locale.h>
#include <fmt/core.h>
#include <fmt/args.h>
#include <fmt/color.h>
#include <fmt/ostream.h>
#include <iomanip>

using namespace log4cxx;
using OutputStreamType = std::basic_ostream<logchar>;

struct MyStruct {
	int x;
};
	OutputStreamType& 
operator<<(OutputStreamType& stream, const MyStruct& mystruct )
{
	stream << LOG4CXX_STR("[MyStruct x: ") << mystruct.x << LOG4CXX_STR("]");
	return stream;
}
#if FMT_VERSION >= (9 * 10000)
template <> struct fmt::formatter<MyStruct> : ostream_formatter {};
#endif

int main()
{
	setlocale(LC_ALL, "");

	BasicConfigurator::configureAsync();
	auto rootLogger = LogManager::getRootLogger();

	LOG4CXX_INFO_FMT_ASYNC( rootLogger, "This is a {} message", "char" );
	LOG4CXX_INFO_FMT_ASYNC( rootLogger, LOG4CXX_STR("This is a {} message"), LOG4CXX_STR("LogString") );
	LOG4CXX_INFO_FMT_ASYNC( rootLogger, LOG4CXX_STR("We can also align text to the {:<10} or {:>10}"), LOG4CXX_STR("left"), LOG4CXX_STR("right") );

	MyStruct mine{ 42 };
	LOG4CXX_INFO_FMT_ASYNC( rootLogger, LOG4CXX_STR("This custom type {} can also be logged, since it implements operator<<"), mine );

	LOG4CXX_INFO_ASYNC( rootLogger, LOG4CXX_STR("Numbers can be formatted with excessive operator<<: ")
				  << std::setprecision(3) << 22.456
				  << LOG4CXX_STR(" And as hex: ")
				  << std::setbase( 16 ) << 123 );
	LOG4CXX_INFO_FMT_ASYNC( rootLogger, LOG4CXX_STR("Numbers can be formatted with a format string {:.1f} and as hex: {:x}"), 22.456, 123 );
	// Uncomment the next line to verify that compile time type checking works
	//LOG4CXX_INFO_FMT_ASYNC( rootLogger, LOG4CXX_STR("Numbers can be formatted with a format string {:.1f} and as hex: {:x}"), "wrong type", 123 );

	LogManager::shutdown();
	return 0;
}
