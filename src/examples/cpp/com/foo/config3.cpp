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
#include "config.h"
#include <log4cxx/logmanager.h>
#include <log4cxx/logstring.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/defaultconfigurator.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/file.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/transcoder.h>

#ifdef _WIN32
#include <windows.h>
#elif __APPLE__
#include <mach-o/dyld.h>
#elif (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 500) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
#include <unistd.h> // getpid
#else
#include <cstring> // strncpy
#endif


// Local functions
namespace {
using namespace log4cxx;

// Get a list of file base names that may contain configuration data
// and put an alternate path into \c altPrefix
auto DefaultConfigurationFileNames(std::string& altPrefix) -> std::vector<std::string> {
	std::vector<std::string> result;

	// Find the executable file name
	static const int bufSize = 4096;
	char buf[bufSize+1] = {0}, pathSepar = '/';
	uint32_t bufCount = 0;
#if defined(_WIN32)
	GetModuleFileName(NULL, buf, bufSize);
	pathSepar = '\\';
#elif defined(__APPLE__)
	_NSGetExecutablePath(buf, &bufCount);
#elif (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 500) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
	std::ostringstream exeLink;
	exeLink << "/proc/" << getpid() << "/exe";
	bufCount = readlink(exeLink.str().c_str(), buf, bufSize);
	if (0 < bufCount)
		buf[bufCount] = 0;
#else
	strncpy(buf, "auto-configured", bufSize);
#endif
	std::string programFileName(buf);
	auto slashIndex = programFileName.rfind(pathSepar);
	if (std::string::npos != slashIndex) {
		// Extract the path
		altPrefix = programFileName.substr(0, slashIndex + 1);
		if (helpers::LogLog::isDebugEnabled())
		{
			LogString msg = LOG4CXX_STR("Alternate prefix [");
			helpers::Transcoder::decode(altPrefix, msg);
			msg += LOG4CXX_STR("]");
			helpers::LogLog::debug(msg);
		}
		// Add a local directory relative name
		result.push_back(programFileName.substr(slashIndex + 1));
		if (helpers::LogLog::isDebugEnabled())
		{
			LogString msg(LOG4CXX_STR("Alternate configuration file name ["));
			helpers::Transcoder::decode(result.back(), msg);
			msg += LOG4CXX_STR("]");
			helpers::LogLog::debug(msg);
		}
		// Add a local directory relative name without any extension
		auto dotIndex = result.back().rfind('.');
		if (std::string::npos != dotIndex)
		{
			result.push_back(result.back());
			result.back().erase(dotIndex);
			if (helpers::LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Alternate configuration file name ["));
				helpers::Transcoder::decode(result.back(), msg);
				msg += LOG4CXX_STR("]");
				helpers::LogLog::debug(msg);
			}
		}
	}
	else if (!programFileName.empty()) {
		auto dotIndex = result.back().rfind('.');
		if (std::string::npos != dotIndex) {
			programFileName.erase(dotIndex);
			result.push_back(programFileName);
			if (helpers::LogLog::isDebugEnabled())
			{
				LogString msg(LOG4CXX_STR("Alternate configuration file name ["));
				helpers::Transcoder::decode(result.back(), msg);
				msg += LOG4CXX_STR("]");
				helpers::LogLog::debug(msg);
			}
		}
	}
	result.push_back("log4cxx");
	result.push_back("log4j");
	return result;
}

// Provide the name of the configuration file to [DefaultConfigurator](@ref log4cxx.DefaultConfigurator).
// Set up a background thread that will check for changes every 5 seconds and reload the configuration
void SelectConfigurationFile() {
#if defined(_DEBUG)
	helpers::LogLog::setInternalDebugging(true);
#endif
	const char* extension[] = { ".xml", ".properties", 0 };
	std::string altPrefix;
	helpers::Pool pool;

	for (auto baseName : DefaultConfigurationFileNames(altPrefix)) {
		int i = 0;
		for (; extension[i]; ++i) {
			File current_working_dir_candidate(baseName + extension[i]);
			if (current_working_dir_candidate.exists(pool)) {
				DefaultConfigurator::setConfigurationFileName(current_working_dir_candidate.getPath());
				DefaultConfigurator::setConfigurationWatchSeconds(5);
				break;
			}
			if (!altPrefix.empty()) {
				File alt_dir_candidate(altPrefix + baseName + extension[i]);
				if (alt_dir_candidate.exists(pool)) {
					DefaultConfigurator::setConfigurationFileName(alt_dir_candidate.getPath());
					DefaultConfigurator::setConfigurationWatchSeconds(5);
					break;
				}
			}
		}
		if (extension[i]) // Found a configuration file?
			return;
	}
	// Configuration file not found - send events to the console
	BasicConfigurator::configure();
}

} // namespace

namespace com { namespace foo {

// Retrieve the \c name logger pointer.
// Configure Log4cxx on the first call.
auto getLogger(const std::string& name) -> LoggerPtr {
	using namespace log4cxx;
	static struct log4cxx_initializer {
		log4cxx_initializer() {
			SelectConfigurationFile();
		}
		~log4cxx_initializer() {
			LogManager::shutdown();
		}
	} initialiser;
	return name.empty()
		? LogManager::getRootLogger()
		: LogManager::getLogger(name);
}

} } // namespace com::foo
