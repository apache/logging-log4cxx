/*
 * Copyright 2003,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

#define LOG4CXX_LOGCHAR_IS_WCHAR 1

namespace log4cxx {

#if LOG4CXX_LOGCHAR_IS_WCHAR
   typedef wchar_t logchar;
#endif

#if LOG4CXX_LOGCHAR_IS_CHAR
   typedef char logchar;
#endif

   typedef std::basic_string<logchar> LogString;


}

#if LOG4CXX_LOGCHAR_IS_WCHAR
#define LOG4CXX_STR(str) L ## str
#endif

#if LOG4CXX_LOGCHAR_IS_CHAR
#define LOG4CXX_STR(str) str
#endif

#if !defined(LOG4CXX_EOL)
#if defined(_WIN32)
#define LOG4CXX_EOL LOG4CXX_STR("\x0D\x0A")
#else
#define LOG4CXX_EOL LOG4CXX_STR("\x0A")
#endif
#endif


#endif //_LOG4CXX_STRING_H
