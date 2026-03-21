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

#ifndef _LOG4CXX_HELPERS_TRANSFORM_H
#define _LOG4CXX_HELPERS_TRANSFORM_H

#include <log4cxx/logstring.h>

namespace LOG4CXX_NS
{
namespace helpers
{
/**
Utility class for transforming strings.
*/
class LOG4CXX_EXPORT Transform
{
	public:
		/**
		* Add \c input, which may contain HTML tags
		* (ie, &lt;b&gt;, &lt;table&gt;, etc) to \c buf
		* while replacing any '<' and '>' characters
		* with respective predefined entity references.
		* Any NUL character in \c input is not copied to \c buf.
		* A character reference is used in place of a character
		* whose value is not permitted by the XML 1.0 specification.
		*
		* @param buf output stream where to write the modified string.
		* @param input The text to be converted.
		* */
		static void appendEscapingTags(
			LogString& buf, const LogString& input);

		/**
		* Add \c input to \c buf while ensuring embedded CDEnd strings (]]&gt;)
		* are handled properly within the message.
		* The initial CDStart (&lt;![CDATA[) and terminating CDEnd (]]&gt;)
		* of the CDATA section must be added by the calling method.
		* Any NUL character in \c input is not copied to \c buf.
		* A character reference is used in place of a character
		* whose value is not permitted by the XML 1.0 specification.
		*
		* @param buf Transformed \c input text is added to this.
		* @param input The text to be appended to \c buf
		*/
		static void appendEscapingCDATA(
			LogString& buf, const LogString& input);

		/**
		* Add \c ch to \c buf as an XML character reference.
		*
		* @param buf output stream holding the XML data to this point.
		* @param ch the value to encode as a XML character reference
		*/
		static void appendCharacterReference(LogString& buf, unsigned int ch);

		/**
		* Append a transformation of \c input onto \c buf.
		* Only the valid XML 1.0 specification characters
		* (#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF])
		* are copied to \c buf.
		* Any special character (&lt;, &gt;, &amp; and &quot;)
		* is replaced with an entity reference.
		*
		* @param buf Transformed \c input text is added to this.
		* @param input The text to be transformed.
		* */
		static void appendLegalCharacters(LogString& buf, const LogString& input);
}; // class Transform
}  // namespace helpers
} //namespace log4cxx

#endif // _LOG4CXX_HELPERS_TRANSFORM_H
