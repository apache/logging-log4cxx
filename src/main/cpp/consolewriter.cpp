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

#include <log4cxx/private/consolewriter_priv.h>
#include <log4cxx/helpers/transcoder.h>
#if !defined(LOG4CXX)
	#define LOG4CXX 1
#endif
#include <log4cxx/private/log4cxx_private.h>

using namespace LOG4CXX_NS;

static bool isConsoleWide(FILE *file)
{
#if LOG4CXX_FORCE_WIDE_CONSOLE
	return true;
#elif LOG4CXX_FORCE_BYTE_CONSOLE || !LOG4CXX_HAS_FWIDE
	return false;
#else
	return fwide(file, 0) > 0;
#endif
}

size_t helpers::writeToConsole(const LogString& str, FILE *file)
{
#if LOG4CXX_WCHAR_T_API
	if (isConsoleWide(file))
	{
		LOG4CXX_ENCODE_WCHAR(msg, str);
		int status = fputws(msg.c_str(), file);
		return status == EOF ? 0 : msg.size();
	}
#endif

	LOG4CXX_ENCODE_CHAR(msg, str);

	//
	// We can't use fputs, fprintf, or even a `%.*s` specifier
	// as the message may contain embedded null bytes, which would cause the
	// message to be prematurely truncated.
	//
	return fwrite(msg.data(), 1, msg.size(), file);
}
