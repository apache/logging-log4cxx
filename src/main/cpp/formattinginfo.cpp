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
#include <log4cxx/pattern/formattinginfo.h>
#include <algorithm>
#include <limits.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::pattern;

struct FormattingInfo::FormattingInfoPrivate
{
	FormattingInfoPrivate(const bool leftAlign1, const int minLength1, const int maxLength1, const bool leftTruncate1):
		minLength(minLength1),
		maxLength(maxLength1),
		leftAlign(leftAlign1),
		leftTruncate(leftTruncate1) {}

	/**
	 * Minimum length.
	 */
	const int minLength;

	/**
	 * Maximum length.
	 */
	const int maxLength;

	/**
	 * Alignment.
	 */
	const bool leftAlign;

	/**
	 * Remove characters from the beginning (true) or the end (false) of a value longer than maxLength.
	 */
	const bool leftTruncate;
};

IMPLEMENT_LOG4CXX_OBJECT(FormattingInfo)

/**
 * Creates new instance.
 * @param leftAlign left align if true.
 * @param minLength minimum length.
 * @param maxLength maximum length.
 */
FormattingInfo::FormattingInfo(
	const bool leftAlign1, const int minLength1, const int maxLength1) :
	FormattingInfo(leftAlign1, minLength1, maxLength1, true)
{
}

/**
 * Creates new instance.
 * @param leftAlign left align if true.
 * @param minLength minimum length.
 * @param maxLength maximum length.
 * @param leftTruncate truncate from the beginning if true, from the end otherwise.
 */
FormattingInfo::FormattingInfo(
	const bool leftAlign1, const int minLength1, const int maxLength1, const bool leftTruncate1) :
	m_priv(std::make_unique<FormattingInfoPrivate>(leftAlign1, minLength1, maxLength1, leftTruncate1))
{
}

FormattingInfo::~FormattingInfo() {}

/**
 * Gets default instance.
 * @return default instance.
 */
FormattingInfoPtr FormattingInfo::getDefault()
{
	static helpers::WideLife<FormattingInfoPtr> def= std::make_shared<FormattingInfo>(false, 0, INT_MAX);
	return def;
}

/**
 * Adjust the content of the buffer based on the specified lengths and alignment.
 *
 * @param fieldStart start of field in buffer.
 * @param buffer buffer to be modified.
 */
void FormattingInfo::adjustField(const LogString::size_type fieldStart, LogString& buffer) const
{
	if (fieldStart > buffer.length())
	{
		return;
	}

	const LogString::size_type rawLength = buffer.length() - fieldStart;
	const LogString::size_type maxLength = static_cast<LogString::size_type>(m_priv->maxLength);
	const LogString::size_type minLength = static_cast<LogString::size_type>(m_priv->minLength);

	if (rawLength > maxLength)
	{
		if (m_priv->leftTruncate)
		{
			buffer.erase(buffer.begin() + fieldStart,
				buffer.begin() + fieldStart + (rawLength - maxLength));
		}
		else
		{
			buffer.erase(fieldStart + maxLength);
		}
	}
	else if (rawLength < minLength)
	{
		if (m_priv->leftAlign)
		{
			buffer.append(minLength - rawLength, (logchar) 0x20 /* ' ' */);
		}
		else
		{
			buffer.insert(fieldStart, minLength - rawLength, 0x20 /* ' ' */);
		}
	}
}

bool FormattingInfo::isLeftAligned() const
{
	return m_priv->leftAlign;
}

int FormattingInfo::getMinLength() const
{
	return m_priv->minLength;
}

int FormattingInfo::getMaxLength() const
{
	return m_priv->maxLength;
}

bool FormattingInfo::isLeftTruncated() const
{
	return m_priv->leftTruncate;
}
