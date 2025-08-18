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

#ifndef _LOG4CXX_HELPERS_SYSTEM_H
#define _LOG4CXX_HELPERS_SYSTEM_H

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/exception.h>

namespace LOG4CXX_NS
{
namespace helpers
{
class Properties;

/** The System class contains several useful class fields and methods.
It cannot be instantiated.
*/
class LOG4CXX_EXPORT System
{
	public:


		/**
		Add to \c props the currently executing program file path
		and the [std::filesystem::path](https://en.cppreference.com/w/cpp/filesystem/path.html)
		decomposition of the currently executing program file path, using the variable names:
		- PROGRAM_FILE_PATH
		- PROGRAM_FILE_PATH.ROOT_NAME
		- PROGRAM_FILE_PATH.ROOT_DIRECTORY
		- PROGRAM_FILE_PATH.ROOT_PATH
		- PROGRAM_FILE_PATH.RELATIVE_PATH
		- PROGRAM_FILE_PATH.PARENT_PATH
		- PROGRAM_FILE_PATH.FILENAME
		- PROGRAM_FILE_PATH.STEM
		- PROGRAM_FILE_PATH.EXTENSION
		*/
		static void addProgramFilePathComponents(Properties& props);

		/**
		The value of the system property associated with \c key.

		@param key the name of the system property.

		@return the string value of the system property.

		@throws IllegalArgumentException if key is empty.
		*/
		static LogString getProperty(const LogString& key);
};
} // namespace helpers
} //  namespace log4cxx

#endif //_LOG4CXX_HELPERS_SYSTEM_H
