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

#include <log4cxx/logstring.h>
#include <log4cxx/helpers/system.h>
#include <log4cxx/helpers/filesystempath.h>

#include <log4cxx/helpers/transcoder.h>
#include <log4cxx/helpers/pool.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/loglog.h>
#include <log4cxx/helpers/stringhelper.h>
#include <apr_file_io.h>
#include <apr_user.h>
#include <apr_env.h>

#ifdef _WIN32
#include <windows.h>
#elif __APPLE__
#include <mach-o/dyld.h>
#elif (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 500) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
#include <unistd.h> // getpid
#endif
#include <sstream>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;


LogString System::getProperty(const LogString& lkey)
{
	if (lkey.empty())
	{
		throw IllegalArgumentException(LOG4CXX_STR("key is empty"));
	}

	LogString rv;

	if (lkey == LOG4CXX_STR("java.io.tmpdir"))
	{
		Pool p;
		const char* dir = NULL;
		apr_status_t stat = apr_temp_dir_get(&dir, p.getAPRPool());

		if (stat == APR_SUCCESS)
		{
			Transcoder::decode(dir, rv);
		}

		return rv;
	}

	if (lkey == LOG4CXX_STR("user.dir"))
	{
		Pool p;
		char* dir = NULL;
		apr_status_t stat = apr_filepath_get(&dir, APR_FILEPATH_NATIVE,
				p.getAPRPool());

		if (stat == APR_SUCCESS)
		{
			Transcoder::decode(dir, rv);
		}

		return rv;
	}

#if APR_HAS_USER

	if (lkey == LOG4CXX_STR("user.home") || lkey == LOG4CXX_STR("user.name"))
	{
		Pool pool;
		apr_uid_t userid;
		apr_gid_t groupid;
		apr_pool_t* p = pool.getAPRPool();
		apr_status_t stat = apr_uid_current(&userid, &groupid, p);

		if (stat == APR_SUCCESS)
		{
			char* username = NULL;
			stat = apr_uid_name_get(&username, userid, p);

			if (stat == APR_SUCCESS)
			{
				if (lkey == LOG4CXX_STR("user.name"))
				{
					Transcoder::decode(username, rv);
				}
				else
				{
					char* dirname = NULL;
					stat = apr_uid_homepath_get(&dirname, username, p);

					if (stat == APR_SUCCESS)
					{
						Transcoder::decode(dirname, rv);
					}
				}
			}
		}

		return rv;
	}

#endif

	LOG4CXX_ENCODE_CHAR(key, lkey);
	Pool p;
	char* value = NULL;
	apr_status_t stat = apr_env_get(&value, key.c_str(),
			p.getAPRPool());

	if (stat == APR_SUCCESS)
	{
		Transcoder::decode((const char*) value, rv);
	}

	return rv;
}

void System::addProgramFilePathComponents(Properties& props)
{
	// Find the executable file name
	static const int bufSize = 4096;
	char buf[bufSize+1] = {0}, pathSepar = '/';
	int bufCount = 0;
#if defined(_WIN32)
	if (0 == GetModuleFileName(NULL, buf, bufSize))
	{
		Pool p;
		LogString lsErrorCode;
		StringHelper::toString((int)GetLastError(), p, lsErrorCode);
		LogLog::warn(LOG4CXX_STR("GetModuleFileName error ") + lsErrorCode);
		return;
	}
	pathSepar = '\\';
#elif defined(__APPLE__)
	bufCount = bufSize;
	if (0 != _NSGetExecutablePath(buf, &bufCount))
	{
		LogLog::warn(LOG4CXX_STR("_NSGetExecutablePath failed"));
		return;
	}
#elif (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 500) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
	std::ostringstream exeLink;
	exeLink << "/proc/" << getpid() << "/exe";
	if ((bufCount = readlink(exeLink.str().c_str(), buf, bufSize)) <= 0)
	{
		LOG4CXX_DECODE_CHAR(lsExeLink, exeLink.str());
		LogLog::warn(LOG4CXX_STR("Failed to read ") + lsExeLink);
		return;
	}
	if (bufSize < bufCount)
		buf[bufSize] = 0;
	else
		buf[bufCount] = 0;
#else
	LogLog::warn(LOG4CXX_STR("Unable to determine the name of the executable file on this system"));
	return;
#endif

	// Add the path to the properties
	std::string programFileName(buf);
	if (programFileName.empty())
	{
		LogLog::warn(LOG4CXX_STR("Current executable's file name is empty"));
		return;
	}
		
	LOG4CXX_DECODE_CHAR(lsProgramFileName, programFileName);
	LogString prefix{ LOG4CXX_STR("PROGRAM_FILE_PATH") };
	props.setProperty(prefix, lsProgramFileName);

#if LOG4CXX_HAS_FILESYSTEM_PATH
	// Add the path components to the properties
	prefix += '.';
	FilesystemPath programPath(programFileName);
#if LOG4CXX_LOGCHAR_IS_WCHAR
	auto root_name = programPath.root_name().wstring();
	props.setProperty(prefix + LOG4CXX_STR("ROOT_NAME"), root_name);
	auto root_directory = programPath.root_directory().wstring();
	props.setProperty(LOG4CXX_STR("ROOT_DIRECTORY"),root_directory);
	auto root_path = programPath.root_path().wstring();
	props.setProperty(prefix + LOG4CXX_STR("ROOT_PATH"), root_path);
	auto relative_path = programPath.relative_path().wstring();
	props.setProperty(prefix + LOG4CXX_STR("RELATIVE_PATH"), relative_path);
	auto parent_path = programPath.parent_path().wstring();
	props.setProperty(prefix + LOG4CXX_STR("PARENT_PATH"), parent_path);
	auto filename = programPath.filename().wstring();
	props.setProperty(prefix + LOG4CXX_STR("FILENAME"), filename);
	auto stem = programPath.stem().wstring();
	props.setProperty(prefix + LOG4CXX_STR("STEM"), stem);
	auto extension = programPath.extension().wstring();
	props.setProperty(prefix + LOG4CXX_STR("EXTENSION"), extension);
#else
	LOG4CXX_DECODE_CHAR(root_name, programPath.root_name().string());
	props.setProperty(prefix + LOG4CXX_STR("ROOT_NAME"), root_name);
	LOG4CXX_DECODE_CHAR(root_directory, programPath.root_directory().string());
	props.setProperty(LOG4CXX_STR("ROOT_DIRECTORY"),root_directory);
	LOG4CXX_DECODE_CHAR(root_path, programPath.root_path().string());
	props.setProperty(prefix + LOG4CXX_STR("ROOT_PATH"), root_path);
	LOG4CXX_DECODE_CHAR(relative_path, programPath.relative_path().string());
	props.setProperty(prefix + LOG4CXX_STR("RELATIVE_PATH"), relative_path);
	LOG4CXX_DECODE_CHAR(parent_path, programPath.parent_path().string());
	props.setProperty(prefix + LOG4CXX_STR("PARENT_PATH"), parent_path);
	LOG4CXX_DECODE_CHAR(filename, programPath.filename().string());
	props.setProperty(prefix + LOG4CXX_STR("FILENAME"), filename);
	LOG4CXX_DECODE_CHAR(stem, programPath.stem().string());
	props.setProperty(prefix + LOG4CXX_STR("STEM"), stem);
	LOG4CXX_DECODE_CHAR(extension, programPath.extension().string());
	props.setProperty(prefix + LOG4CXX_STR("EXTENSION"), extension);
#endif
#endif // LOG4CXX_HAS_FILESYSTEM_PATH
}
