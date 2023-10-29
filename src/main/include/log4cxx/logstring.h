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

#ifndef _LOG4CXX_STRING_H
#define _LOG4CXX_STRING_H

#include <string>
#include <log4cxx/log4cxx.h>

#if (LOG4CXX_LOGCHAR_IS_WCHAR + LOG4CXX_LOGCHAR_IS_UTF8 + LOG4CXX_LOGCHAR_IS_UNICHAR)>1
	#error only one of LOG4CXX_LOGCHAR_IS_WCHAR, LOG4CXX_LOGCHAR_IS_UTF8 or LOG4CXX_LOGCHAR_IS_UNICHAR may be true
#endif

#if LOG4CXX_CFSTRING_API
extern "C" {
	typedef const struct __CFString* CFStringRef;
}
#endif

namespace LOG4CXX_NS
{

#if LOG4CXX_LOGCHAR_IS_UNICHAR || LOG4CXX_UNICHAR_API
	typedef unsigned short UniChar;
#endif

#if LOG4CXX_LOGCHAR_IS_WCHAR
	typedef wchar_t logchar;
	#define LOG4CXX_STR(str) L ## str
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
	typedef char logchar;
	#if LOG4CXX_CHARSET_EBCDIC
		#define LOG4CXX_STR(str) LOG4CXX_NS::helpers::Transcoder::decode(str)
	#else
		#define LOG4CXX_STR(str) str
	#endif
#endif

#if LOG4CXX_LOGCHAR_IS_UNICHAR
	typedef UniChar logchar;
	#define LOG4CXX_STR(str) LOG4CXX_NS::helpers::Transcoder::decode(str)
#endif

typedef std::basic_string<logchar> LogString;

}

#if !defined(LOG4CXX_EOL)
	#if defined(_WIN32)
		#define LOG4CXX_EOL LOG4CXX_STR("\x0D\x0A")
	#else
		#define LOG4CXX_EOL LOG4CXX_STR("\x0A")
	#endif
#endif


#if LOG4CXX_LOGCHAR_IS_UNICHAR || (LOG4CXX_LOGCHAR_IS_UTF8 || LOG4CXX_CHARSET_EBCDIC)
	#include <log4cxx/helpers/transcoder.h>
#endif

#endif //_LOG4CXX_STRING_H
