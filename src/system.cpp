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

#include <log4cxx/helpers/system.h>

#if defined(LOG4CXX_HAVE_FTIME)
#include <sys/timeb.h>
#endif

#if defined(LOG4CXX_HAVE_GETTIMEOFDAY)
#include <sys/time.h>
#endif

#include <time.h>
#include <log4cxx/helpers/properties.h>
#include <log4cxx/helpers/transcoder.h>

using namespace log4cxx;
using namespace log4cxx::helpers;


LogString System::getProperty(const LogString& lkey)
{
	if (lkey.empty())
	{
		throw IllegalArgumentException();
	}

        LOG4CXX_ENCODE_CHAR(key, lkey);
        LogString rv;
	const char * value = ::getenv(key.c_str());
	if (value != 0) {
                Transcoder::decode(value, rv);
	}
        return rv;
}

