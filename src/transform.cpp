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

#include <log4cxx/helpers/transform.h>

using namespace log4cxx;
using namespace log4cxx::helpers;



void Transform::appendEscapingTags(
	LogString& buf, const LogString& input)
{
	//Check if the string is zero length -- if so, return
	//what was sent in.

	if(input.length() == 0 )
	{
		return;
	}

	LogString::const_iterator it = input.begin();
	LogString::const_iterator itEnd = input.end();
	logchar ch;
	while(it != itEnd)
	{
		ch = *it++;
		if(ch == LOG4CXX_STR('<'))
		{
			buf.append(LOG4CXX_STR("&lt;"));
		}
		else if(ch == LOG4CXX_STR('>'))
		{
			buf.append(LOG4CXX_STR("&gt;"));
		}
		else
		{
			buf.append(1, ch);
		}
	}
}

void Transform::appendEscapingCDATA(
	LogString& buf, const LogString& input)
{
     static const LogString CDATA_END(LOG4CXX_STR("]]>"));
     static const LogString CDATA_EMBEDED_END(LOG4CXX_STR("]]>]]&gt;<![CDATA["));

     const LogString::size_type CDATA_END_LEN = 3;


	if(input.length() == 0 )
	{
		return;
	}

	LogString::size_type end = input.find(CDATA_END);
	if (end == LogString::npos)
	{
		buf.append(input);
		return;
	}

	LogString::size_type start = 0;
	while (end != LogString::npos)
	{
		buf.append(input, start, end-start);
		buf.append(CDATA_EMBEDED_END);
		start = end + CDATA_END_LEN;
		if (start < input.length())
		{
			end = input.find(CDATA_END, start);
		}
		else
		{
			return;
		}
	}

	buf.append(input, start, input.length() - start);
}

