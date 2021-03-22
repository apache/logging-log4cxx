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
#include <log4cxx/basicconfigurator.h>
#include <locale.h>
#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/ostream.h>
#include <iomanip>

using namespace log4cxx;
using namespace log4cxx::helpers;

struct MyStruct {
		int x;
};

std::ostream& operator<<( std::ostream& stream, const MyStruct& mystruct ){
		stream << "[MyStruct x:" << mystruct.x << "]";
		return stream;
}

int main()
{
	setlocale(LC_ALL, "");

	BasicConfigurator::configure();
	LoggerPtr rootLogger = Logger::getRootLogger();

	LOG4CXX_INFO_FMT( rootLogger, "This is a {} mesage", "test" );
	LOG4CXX_INFO_FMT( rootLogger, fmt::fg(fmt::color::red), "Messages can be colored" );
	LOG4CXX_INFO_FMT( rootLogger, "We can also align text to the {:<10} or {:>10}", "left", "right" );

	MyStruct mine;
	LOG4CXX_INFO_FMT( rootLogger, "This custom type {} can also be logged, since it implements operator<<", mine );

	LOG4CXX_INFO( rootLogger, "Numbers can be formatted with excessive operator<<: "
				  << std::setprecision(3) << 22.456
				  << " And as hex: "
				  << std::setbase( 16 ) << 123 );
	LOG4CXX_INFO_FMT( rootLogger, "Numbers can be formatted with a format string {:.1f} and as hex: {:x}", 22.456, 123 );

	return 0;
}
