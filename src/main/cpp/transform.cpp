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
#include <log4cxx/helpers/transform.h>
#include <log4cxx/helpers/widelife.h>
#include <functional>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::helpers;

namespace
{
using CharProcessor = std::function<void(LogString&, int)>;

void appendValidCharacters(LogString& buf, const LogString& input, CharProcessor handler = {})
{
	static const logchar specials[] =
		{ 0x22 /* " */
		, 0x26 /* & */
		, 0x3C /* < */
		, 0x3E /* > */
		, 0x00
		};
	auto start = input.begin();
	for (auto nextCodePoint = start; input.end() != nextCodePoint; )
	{
		auto lastCodePoint = nextCodePoint;
		auto ch = Transcoder::decode(input, nextCodePoint);
		// Allowable XML 1.0 characters are:
		// #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
		if (0x20 <= ch && ch <= 0xD7FF)
		{
			auto pSpecial = &specials[0];
			while (*pSpecial && *pSpecial != ch)
				++pSpecial;
			if (!*pSpecial)
				continue;
		}
		else if (0x9 == ch || 0xA == ch || 0xD == ch ||
				(0xE000 <= ch && ch <= 0xFFFD) ||
				(0x10000 <= ch && ch <= 0x10FFFF))
		{
			continue;
		}

		if (start != lastCodePoint)
			buf.append(start, lastCodePoint);
		start = nextCodePoint;
		switch (ch)
		{
			case 0: // Do not output a NUL character
				break;
			case 0x22:
				buf.append(LOG4CXX_STR("&quot;"));
				break;

			case 0x26:
				buf.append(LOG4CXX_STR("&amp;"));
				break;

			case 0x3C:
				buf.append(LOG4CXX_STR("&lt;"));
				break;

			case 0x3E:
				buf.append(LOG4CXX_STR("&gt;"));
				break;

			default:
				if (handler)
					handler(buf, ch);
				break;
		}
	}
	buf.append(start, input.end());
}

} // namespace

void Transform::appendEscapingCDATA(
	LogString& buf, const LogString& input)
{
	static const LogString CDATA_END(LOG4CXX_STR("]]>"));
	const LogString::size_type CDATA_END_LEN = 3;
	static const LogString CDATA_EMBEDED_END(LOG4CXX_STR("]]&gt;<![CDATA["));
	auto start = input.begin();
	for (auto nextCodePoint = start; input.end() != nextCodePoint; )
	{
		auto lastCodePoint = nextCodePoint;
		auto ch = Transcoder::decode(input, nextCodePoint);
		bool cdataEnd = false;
		// Allowable XML 1.0 characters are:
		// #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
		if (CDATA_END[0] == ch && input.end() != nextCodePoint)
		{
			if (CDATA_END[1] != Transcoder::decode(input, nextCodePoint) ||
				input.end() == nextCodePoint)
			{
				--nextCodePoint;
				continue;
			}
			if (CDATA_END[2] != Transcoder::decode(input, nextCodePoint))
			{
				--nextCodePoint;
				--nextCodePoint;
				continue;
			}
			cdataEnd = true;
		}
		else if (0x9 == ch || 0xA == ch || 0xD == ch ||
				(0x20 <= ch && ch <= 0xD7FF) ||
				(0xE000 <= ch && ch <= 0xFFFD) ||
				(0x10000 <= ch && ch <= 0x10FFFF))
		{
			continue;
		}

		if (start != lastCodePoint)
			buf.append(start, lastCodePoint);
		if (cdataEnd)
			buf.append(CDATA_EMBEDED_END);
		else if (0 != ch)
			appendCharacterReference(buf, ch);
		start = nextCodePoint;
	}
	buf.append(start, input.end());
}

void Transform::appendCharacterReference(LogString& buf, int ch)
{
	auto toHexDigit = [](int ch) -> int
	{
		return (10 <= ch ? (0x61 - 10) : 0x30) + ch;
	};
	buf.push_back('&');
	buf.push_back('#');
	buf.push_back('x');
	if (0xFFFFFFF < ch)
		buf.push_back(toHexDigit((ch & 0x70000000) >> 28));
	if (0xFFFFFF < ch)
		buf.push_back(toHexDigit((ch & 0xF000000) >> 24));
	if (0xFFFFF < ch)
		buf.push_back(toHexDigit((ch & 0xF00000) >> 20));
	if (0xFFFF < ch)
		buf.push_back(toHexDigit((ch & 0xF0000) >> 16));
	if (0xFFF < ch)
		buf.push_back(toHexDigit((ch & 0xF000) >> 12));
	if (0xFF < ch)
		buf.push_back(toHexDigit((ch & 0xF00) >> 8));
	if (0xF < ch)
		buf.push_back(toHexDigit((ch & 0xF0) >> 4));
	buf.push_back(toHexDigit(ch & 0xF));
	buf.push_back(';');
}

void Transform::appendEscapingTags(LogString& buf, const LogString& input)
{
	appendValidCharacters(buf, input, appendCharacterReference);
}

void Transform::appendLegalCharacters(LogString& buf, const LogString& input)
{
	appendValidCharacters(buf, input);
}
